"""
tests/test_interactive.py — the interactive mode: command parsing and the
session (gittrace.cli.session), the Textual app driven headless
(gittrace.cli.interactive), and the entry point that opens it only for
`gittrace` alone in a terminal (gittrace.cli.main).

No FalkorDB and no model: the FalkorDB check is stubbed, scans run with
--offline --no-llm, and the commands that would need a graph are faked.
"""

from __future__ import annotations

import asyncio
import io
import json
import logging
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from rich.console import Console
from textual.widgets import RichLog, Static

import expected_sample_app
from gittrace import __version__
from gittrace import cli
from gittrace.cli import interactive, logo, session
from gittrace.cli.interactive import GitTraceApp, HistoryInput, Logo, animation_allowed
from gittrace.cli.session import Command, CommandError, Session, parse

ROOT = expected_sample_app.ROOT
REPO = Path(__file__).resolve().parents[1]
UP = lambda: ("up", "local")          # noqa: E731


def _console(width: int = 140) -> Console:
    return Console(file=io.StringIO(), width=width, color_system=None, highlight=False, soft_wrap=False)


def _text(console: Console) -> str:
    return console.file.getvalue()


def _run(coro):
    return asyncio.run(coro)


def _output(app: GitTraceApp) -> str:
    return "\n".join(strip.text for strip in app.query_one(RichLog).lines)


# -- parsing --------------------------------------------------------------------


class TestParse:
    def test_empty_line(self):
        assert parse("") is None and parse("   ") is None

    def test_commands_and_arguments(self):
        assert parse("/scan") == Command("/scan")
        assert parse("/scan app --offline --no-llm") == Command("/scan", ("app",), frozenset({"--offline", "--no-llm"}))
        assert parse("/trace app/db.py:17") == Command("/trace", ("app/db.py:17",))
        assert parse("/blast-radius app/db.py::Repo.get_user").args == ("app/db.py::Repo.get_user",)

    def test_names_ignore_case_and_exit_is_quit(self):
        assert parse("/SCAN").name == "/scan"
        assert parse("/exit") == Command("/quit")

    def test_quotes_and_windows_paths(self):
        assert parse('/scan "my project" --offline').args == ("my project",)
        assert parse(r"/explain C:\code\app").args == (r"C:\code\app",)

    @pytest.mark.parametrize("line, message", [
        ("scan .", "start with a slash"),
        ("/nope", "unknown command /nope"),
        ("/scan . --format json", "/scan has no option --format"),
        ("/trace", "usage: /trace <file:line>"),
        ("/scan a b", "usage: /scan [path]"),
        ("/help me", "usage: /help"),
        ('/scan "unclosed', "cannot read the command"),
    ])
    def test_errors(self, line, message):
        with pytest.raises(CommandError, match=message.replace("[", r"\[").replace("]", r"\]")):
            parse(line)

    def test_every_command_has_a_spec(self):
        assert set(session.NAMES) == {"/scan", "/explain", "/trace", "/blast-radius", "/model", "/help", "/quit"}


# -- the session ----------------------------------------------------------------


class TestSession:
    def test_scan_offline_draws_like_the_cli(self):
        s, c = Session(), _console()
        s.run(parse(f'/scan "{ROOT}" --offline --no-llm --no-blame'), c)
        out = _text(c)
        assert "gittrace scan · sample_app" in out
        assert "GT-SQLI-001" in out and "app/db.py:17" in out
        assert "model triage off (--no-llm)" in out
        assert "Tr0*********" in out                    # secrets stay masked
        assert s.project == ROOT

    def test_scan_reports_status(self):
        seen = []
        Session().run(parse(f'/scan "{ROOT}" --offline --no-llm --no-blame'), _console(), seen.append)
        assert seen and seen[0].startswith("scanning ")

    def test_scan_errors(self, tmp_path, monkeypatch):
        with pytest.raises(CommandError, match="not a directory"):
            Session().run(parse(f'/scan "{tmp_path / "missing"}" --offline'), _console())
        with pytest.raises(CommandError, match="cannot be combined with --no-llm"):
            Session().run(parse(f'/scan "{ROOT}" --fix --no-llm'), _console())

        def down(*args, **kwargs):
            raise RuntimeError("FalkorDB connect/ping failed")
        monkeypatch.setattr("gittrace.core.scan.scan", down)
        with pytest.raises(CommandError, match="add --offline"):
            Session().run(parse(f'/scan "{ROOT}" --no-llm'), _console())

    def test_scan_defaults_to_the_current_project(self):
        s, c = Session(project=ROOT), _console()
        s.run(parse("/scan --offline --no-llm --no-blame"), c)
        assert "sample_app" in _text(c)

    def test_explain_facts_only(self):
        s, c = Session(), _console()
        s.run(parse(f'/explain "{ROOT}" --no-llm'), c)
        out = _text(c)
        assert "GitTrace explain · sample_app" in out
        assert "Endpoints" in out and "app/routers/users.py::read_user" in out

    def test_explain_asks_for_yes_above_ten_minutes(self, monkeypatch):
        from gittrace.llm import explain as summaries

        monkeypatch.setattr(summaries, "estimate_seconds", lambda calls, model=None: 3600.0)
        monkeypatch.setattr(summaries.Explainer, "execute",
                            lambda *a, **k: pytest.fail("no model call without --yes"))
        c = _console()
        Session().run(parse(f'/explain "{ROOT}"'), c)
        assert "about 60 minutes. Add --yes" in _text(c)

    def test_trace_and_blast_radius_errors(self, monkeypatch):
        monkeypatch.setattr("gittrace.core.tools.trace_attack_path",
                            lambda project, target, depth: {"error": f"no graph for {project}"})
        with pytest.raises(CommandError, match="no graph for"):
            Session(project=ROOT).run(parse("/trace app/db.py:17"), _console())

        def down(*args):
            raise RuntimeError("FalkorDB connect/ping failed")
        monkeypatch.setattr("gittrace.core.tools.blast_radius", down)
        with pytest.raises(CommandError, match="FalkorDB connect/ping failed"):
            Session(project=ROOT).run(parse("/blast-radius app/db.py::Repo.get_user"), _console())

    def test_trace_uses_the_current_project(self, monkeypatch):
        calls = []
        monkeypatch.setattr("gittrace.core.tools.trace_attack_path",
                            lambda project, target, depth: calls.append((project, target)) or {"error": "x"})
        with pytest.raises(CommandError):
            Session(project=ROOT).run(parse("/trace app/db.py:17"), _console())
        assert calls == [(str(ROOT), "app/db.py:17")]

    def test_model(self, monkeypatch):
        monkeypatch.delenv("GITTRACE_MODEL", raising=False)
        monkeypatch.delenv("GITTRACE_EXPLAIN_MODEL", raising=False)
        s = Session()
        assert (s.scan_model(), s.explain_model()) == ("ollama/llama3.1:8b", "ollama/qwen2.5-coder:7b")
        c = _console()
        s.run(parse("/model ollama/foo:1b"), c)
        assert (s.scan_model(), s.explain_model()) == ("ollama/foo:1b", "ollama/foo:1b")
        assert _text(c).count("ollama/foo:1b") == 2
        s.run(parse("/model default"), _console())
        assert s.model is None and s.scan_model() == "ollama/llama3.1:8b"

    def test_help_lists_every_usage_verbatim(self):
        c = _console(200)
        Session().run(parse("/help"), c)
        for spec in session.SPECS.values():
            assert spec.command in _text(c)                 # "[path]" is not eaten as markup
            assert spec.options in _text(c)
            assert f"{spec.command} {spec.options}".strip() == spec.usage

    def test_command_and_options(self):
        scan = session.SPECS["/scan"]
        assert scan.command == "/scan [path]" and scan.options.startswith("[--offline] [--no-llm]")
        assert session.SPECS["/model"].command == "/model [name | default]" and not session.SPECS["/model"].options


# -- the app --------------------------------------------------------------------


class BlockingSession(Session):
    """/scan waits for `release`, logs a warning and prints a line, or raises."""

    def __init__(self, fail: bool = False):
        super().__init__(project=ROOT)
        self.release = threading.Event()
        self.fail = fail

    def scan(self, cmd, console, status):
        status("scanning slowly")
        self.release.wait(10)
        logging.getLogger("gittrace.test").warning("a warning from the scan")
        if self.fail:
            raise CommandError("the scan broke")
        console.print("scan output")


async def _submit(pilot, app: GitTraceApp, line: str) -> None:
    app.query_one(HistoryInput).value = line
    await pilot.press("enter")
    await pilot.pause()


async def _until(pilot, condition, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "timed out"
        await pilot.pause(0.05)


class TestApp:
    def test_header(self, monkeypatch):
        monkeypatch.delenv("GITTRACE_MODEL", raising=False)
        monkeypatch.delenv("GITTRACE_EXPLAIN_MODEL", raising=False)

        async def go():
            app = GitTraceApp(Session(project=ROOT), animate=False, falkordb=UP)
            async with app.run_test(size=(120, 40)) as pilot:
                await _until(pilot, lambda: app.falkordb is not None)
                info = str(app.query_one("#info", Static).render())
                assert "GitTrace" in info and f"v{__version__}" in info
                assert str(ROOT) in info
                assert "model     scan     ollama/llama3.1:8b\n" in info          # one line each
                assert "\n          explain  ollama/qwen2.5-coder:7b\n" in info
                assert "● up  local" in info
                assert app.query_one("#header").outer_size.height <= 14 + 2
                assert app.query_one(Logo).outer_size.height <= 14
        _run(go())

    def test_header_shows_falkordb_down(self):
        async def go():
            app = GitTraceApp(animate=False, falkordb=lambda: ("down", "local"))
            async with app.run_test(size=(120, 40)) as pilot:
                await _until(pilot, lambda: app.falkordb is not None)
                assert "● down" in str(app.query_one("#info", Static).render())
        _run(go())

    def test_help_model_and_errors(self):
        async def go():
            app = GitTraceApp(animate=False, falkordb=UP)
            async with app.run_test(size=(120, 40)) as pilot:
                await _submit(pilot, app, "/help")
                await _submit(pilot, app, "/model ollama/foo:1b")
                await _submit(pilot, app, "/nope")
                out = _output(app)
                assert "› /help" in out and "/blast-radius <function-id>" in out
                assert "error: unknown command /nope" in out
                assert "ollama/foo:1b" in str(app.query_one("#info", Static).render())
        _run(go())

    @pytest.mark.parametrize("columns, side_by_side", [(80, False), (100, True), (200, True)])
    def test_help_layout(self, columns, side_by_side):
        """Every description whole (no "…"), right beside its command (2 spaces
        after the command column) or, when narrow, on the next line, indented."""
        async def go():
            app = GitTraceApp(animate=False, falkordb=UP)
            async with app.run_test(size=(columns, 60)) as pilot:
                output = app.query_one(RichLog)
                output.clear()
                await _submit(pilot, app, "/help")
                lines = [strip.text.rstrip() for strip in output.lines]
                assert output.virtual_size.width <= output.scrollable_content_region.width  # no sideways scroll
                return lines

        lines = _run(go())
        block = " ".join(" ".join(lines).split())
        assert "…" not in block
        specs = list(session.SPECS.values())
        width = max(len(s.command) for s in specs)
        for spec in specs:
            assert " ".join(f"{spec.help} {'options: ' + spec.options if spec.options else ''}".split()) in block
            row = next(i for i, line in enumerate(lines) if line.startswith(spec.command))
            if side_by_side:
                assert lines[row] == f"{spec.command:<{width}}  {lines[row][width + 2:]}"
                assert spec.help.startswith(lines[row][width + 2:].split()[0])
            else:
                assert lines[row] == spec.command
                assert lines[row + 1].startswith("    " + spec.help.split()[0])
        first = lines.index(specs[0].command) if not side_by_side else 1
        hint = next(i for i, line in enumerate(lines) if line.startswith("Up and down arrows"))
        assert first == 1 and "" not in lines[first:hint]               # no blank lines between entries
        if columns >= 200:                                               # one line each, plus the options
            assert hint - first == len(specs) + sum(1 for s in specs if s.options)

    def test_quit(self, monkeypatch):
        async def go():
            app = GitTraceApp(animate=False, falkordb=UP)
            exits = []
            monkeypatch.setattr(app, "exit", lambda *a, **k: exits.append(True))
            async with app.run_test(size=(120, 40)) as pilot:
                await _submit(pilot, app, "/quit")
                await _submit(pilot, app, "/exit")
            assert exits == [True, True]
        _run(go())

    def test_history(self):
        async def go():
            app = GitTraceApp(animate=False, falkordb=UP)
            async with app.run_test(size=(120, 40)) as pilot:
                prompt = app.query_one(HistoryInput)
                await _submit(pilot, app, "/help")
                await _submit(pilot, app, "/model x")
                prompt.value = "/sc"                    # a draft is kept
                await pilot.press("up")
                assert prompt.value == "/model x"
                await pilot.press("up")
                assert prompt.value == "/help"
                await pilot.press("up")
                assert prompt.value == "/help"         # stays at the oldest
                await pilot.press("down")
                assert prompt.value == "/model x"
                await pilot.press("down")
                assert prompt.value == "/sc"
                assert prompt.history == ["/help", "/model x"]
        _run(go())

    def test_a_command_runs_off_the_ui_thread_and_pauses_the_logo(self):
        async def go():
            s = BlockingSession()
            app = GitTraceApp(s, animate=True, falkordb=UP)
            async with app.run_test(size=(120, 40)) as pilot:
                spinner = app.query_one(Logo)
                assert spinner.spinning                 # the launch turn
                await _submit(pilot, app, "/scan")
                assert app.busy and not spinner.spinning and spinner.busy
                await _until(pilot, lambda: "scanning slowly" in str(app.query_one("#status", Static).render()))
                await _submit(pilot, app, "/help")      # refused while busy, text kept
                assert "still running" in str(app.query_one("#status", Static).render())
                assert app.query_one(HistoryInput).value == "/help"
                s.release.set()
                await _until(pilot, lambda: not app.busy)
                out = _output(app)
                assert "scan output" in out
                assert "WARNING gittrace.test: a warning from the scan" in out     # log goes to the output
                assert "/scan done in" in str(app.query_one("#status", Static).render())
                assert not spinner.busy
        _run(go())

    def test_command_error_is_shown(self):
        async def go():
            s = BlockingSession(fail=True)
            s.release.set()
            app = GitTraceApp(s, animate=False, falkordb=UP)
            async with app.run_test(size=(120, 40)) as pilot:
                await _submit(pilot, app, "/scan")
                await _until(pilot, lambda: not app.busy)
                assert "error: the scan broke" in _output(app)
                assert "/scan failed in" in str(app.query_one("#status", Static).render())
        _run(go())


class TestHeaderAndHints:
    def test_header_never_names_the_host(self, monkeypatch):
        from gittrace.graph import connection

        host = "r-secret1234.instance-x.gcp.example.cloud"
        monkeypatch.setattr(connection, "FALKORDB_HOST", host)
        monkeypatch.setattr(connection, "FALKORDB_PORT", 54824)
        monkeypatch.setattr(connection, "check", lambda: (False, "TimeoutError: <remote host>"))

        async def go():
            app = GitTraceApp(animate=False)               # the real status function
            async with app.run_test(size=(160, 40)) as pilot:
                await _until(pilot, lambda: app.falkordb is not None)
                info = str(app.query_one("#info", Static).render())
                assert "● down  remote" in info
                assert host not in info and "secret1234" not in info and "54824" not in info
        _run(go())

    def test_local_down_says_how_to_start_it(self):
        async def go():
            app = GitTraceApp(animate=False, falkordb=lambda: ("down", "local"))
            async with app.run_test(size=(160, 40)) as pilot:
                await _until(pilot, lambda: app.falkordb is not None)
                assert "docker compose up -d falkordb" in str(app.query_one("#info", Static).render())
        _run(go())

    def test_first_run_hint(self, tmp_path):
        assert session.first_hint(REPO).startswith("try /scan tests/fixtures/sample_app")
        assert session.first_hint(tmp_path).startswith("try /scan .")

        async def go(project, expected):
            app = GitTraceApp(Session(project=project), animate=False, falkordb=UP)
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause()
                lines = [s.text.strip() for s in app.query_one(RichLog).lines]
                assert lines[0].startswith(expected) and len(lines) == 1
        _run(go(REPO, "try /scan tests/fixtures/sample_app"))
        _run(go(tmp_path, "try /scan ."))

    def test_parse_failure_is_reported_once(self):
        async def go():
            app = GitTraceApp(animate=False, falkordb=UP)
            async with app.run_test(size=(160, 40)) as pilot:
                await _submit(pilot, app, f'/scan "{ROOT}" --offline --no-llm --no-blame')
                await _until(pilot, lambda: not app.busy)
                out = _output(app)
                assert out.count("half_merged.py") == 1 and "Not scanned (parse failures)" in out
                assert "WARNING" not in out
        _run(go())


class TestAnimation:
    def test_allowed(self):
        assert animation_allowed(False, {}) is True
        assert animation_allowed(True, {}) is False
        assert animation_allowed(False, {"NO_COLOR": "1"}) is False
        assert animation_allowed(False, {"NO_COLOR": ""}) is True      # no-color.org: set and non-empty

    def test_no_anim_shows_the_static_frame(self):
        async def go():
            app = GitTraceApp(animate=False, falkordb=UP)
            async with app.run_test(size=(120, 40)) as pilot:
                spinner = app.query_one(Logo)
                await pilot.pause(0.3)
                assert spinner._spin is None and not spinner.spinning
                assert str(spinner.render()) == "\n".join(logo.static_frame())
        _run(go())

    def test_turn_then_hold_then_turn(self):
        async def go():
            app = GitTraceApp(animate=True, falkordb=UP)
            async with app.run_test(size=(120, 40)) as pilot:
                spinner = app.query_one(Logo)
                assert spinner.spinning
                spinner.index = logo.FRAMES - 1
                spinner._tick()                          # the last frame of a turn
                assert spinner.index == 0 and not spinner.spinning and spinner._hold is not None
                assert str(spinner.render()) == "\n".join(logo.static_frame())
                spinner._turn()                          # what the hold timer calls
                assert spinner.spinning and spinner._hold is None
        _run(go())

    def test_pause_mid_turn_resumes_the_turn(self):
        async def go():
            app = GitTraceApp(animate=True, falkordb=UP)
            async with app.run_test(size=(120, 40)) as pilot:
                spinner = app.query_one(Logo)
                spinner.set_busy(True)
                frozen = spinner.index = 7
                await pilot.pause(0.3)
                assert spinner.index == frozen and not spinner.spinning
                spinner.set_busy(False)
                assert spinner.spinning                  # finishes the interrupted turn
                spinner.set_busy(True)
                spinner.index = 0
                spinner.set_busy(False)                  # at rest: wait, then turn
                assert not spinner.spinning and spinner._hold is not None
        _run(go())

    def test_small_terminal_shows_the_static_frame(self):
        async def go():
            app = GitTraceApp(animate=True, falkordb=UP)
            async with app.run_test(size=(70, 20)) as pilot:
                spinner = app.query_one(Logo)
                await pilot.pause(0.2)
                assert not spinner.fits and not spinner.spinning and spinner.index == 0
                assert str(spinner.render()) == "\n".join(logo.static_frame())
                await pilot.resize_terminal(120, 40)
                await pilot.pause(0.2)
                assert spinner.fits
        _run(go())


# -- the entry point ------------------------------------------------------------


class TestEntryPoint:
    def _tty(self, monkeypatch, tty: bool):
        monkeypatch.setattr(sys.stdin, "isatty", lambda: tty, raising=False)
        monkeypatch.setattr(sys.stdout, "isatty", lambda: tty, raising=False)

    def test_only_no_arguments_in_a_terminal_is_interactive(self, monkeypatch):
        self._tty(monkeypatch, True)
        assert cli._interactive([]) and cli._interactive(["--no-anim"])
        assert not cli._interactive(["scan", "."]) and not cli._interactive(["--help"])
        self._tty(monkeypatch, False)
        assert not cli._interactive([])

    @pytest.mark.parametrize("argv, no_anim", [(["gittrace"], False), (["gittrace", "--no-anim"], True)])
    def test_main_opens_the_interactive_mode(self, monkeypatch, argv, no_anim):
        self._tty(monkeypatch, True)
        calls = []
        monkeypatch.setattr(interactive, "run", lambda no_anim: calls.append(no_anim) or 0)
        monkeypatch.setattr(sys, "argv", argv)
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 0 and calls == [no_anim]

    def _gittrace(self, *args):
        return subprocess.run([sys.executable, "-m", "gittrace", *args], cwd=REPO, capture_output=True,
                              text=True, encoding="utf-8", stdin=subprocess.DEVNULL, timeout=120)

    def test_without_a_terminal_no_arguments_prints_the_help(self):
        from typer.testing import CliRunner

        proc = self._gittrace()
        before = CliRunner().invoke(cli.app, [])        # what the Typer app does on its own
        assert proc.returncode == before.exit_code
        assert "Usage:" in proc.stdout + proc.stderr and "scan" in proc.stdout + proc.stderr

    def test_without_a_terminal_no_anim_is_an_error(self):
        proc = self._gittrace("--no-anim")
        assert proc.returncode == cli.EXIT_ERROR and "needs a terminal" in proc.stderr

    def test_commands_still_work_through_main(self):
        proc = self._gittrace("scan", str(ROOT), "--offline", "--no-llm", "--no-blame", "--format", "json",
                              "--fail-on", "none")
        assert proc.returncode == 0, proc.stderr
        assert len(json.loads(proc.stdout)["findings"]) == 13
