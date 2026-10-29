"""
gittrace.cli — the command line (Typer).

    gittrace scan <path> [--format rich|json] [--min-severity LEVEL] [--depth N]
                         [--fail-on LEVEL|none] [--offline] [--no-blame] [--include-tests]
                         [--model NAME] [--no-llm] [--fix]
    gittrace trace <file:line | finding-id> [--project PATH] [--depth N] [--format ...]
    gittrace blast-radius <function-id> [--project PATH] [--depth N] [--format ...]
    gittrace explain <path> [--format rich|md|json] [--out FILE] [--file PATH | --function ID]
                            [--all] [--min-callers N] [--depth N] [--model NAME] [--no-llm] [--yes]

`scan` asks a model (gittrace.llm; --model, else $GITTRACE_MODEL, else
ollama/llama3.1:8b) to triage each finding it shows, unless --no-llm.
Test-code findings are not triaged unless --include-tests. With --fix it
also asks for a fix and shows it as a checked diff (never applied).

`explain` describes the project in plain language (gittrace.core.explain for
the facts, gittrace.llm.explain for the summaries). It writes no graph. Its
model is chosen separately (--model, else $GITTRACE_EXPLAIN_MODEL, else
ollama/qwen2.5-coder:7b; see gittrace.llm.client for why).

`gittrace` with no arguments (or only --no-anim) in a terminal opens the
interactive mode (gittrace.cli.interactive, Textual) with the same commands
as slash commands. Without a terminal (a pipe, CI) it prints this help, as
before; every other invocation is the CLI unchanged.

Exit codes: 0 ok; 1 `scan` found something at or above --fail-on (default
high), so it can gate CI; the gate reads the rules' severity, never the
model's adjustment; 2 an error (bad arguments, no graph or an out-of-date one,
the model cannot be called).

Until the package is installed with its `gittrace` entry point (Phase 7),
run it as `python -m gittrace ...`.
"""

from __future__ import annotations

import json
import logging
import sys
from enum import Enum
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape
from rich.text import Text

from gittrace.cli import render
from gittrace.core.reachability import DEFAULT_DEPTH, MAX_DEPTH
from gittrace.rules.base import severity_rank

# pretty_exceptions_show_locals=False: a traceback must never print local variables (a password
# in the connection code, a secret from scanned source).
app = typer.Typer(add_completion=False, no_args_is_help=True, pretty_exceptions_show_locals=False,
                  help="Find vulnerabilities reachable from your API routes. "
                       "Run `gittrace` with no arguments in a terminal for the interactive mode "
                       "(`gittrace --no-anim`: without the logo animation).")

EXIT_FINDINGS = 1
EXIT_ERROR = 2


def _show_version(value: bool) -> None:
    if value:
        from gittrace import __version__

        typer.echo(f"gittrace {__version__}")
        raise typer.Exit()


@app.callback()
def _root(version: bool = typer.Option(False, "--version", callback=_show_version, is_eager=True,
                                       help="Show the version and exit.")) -> None:
    pass


class Format(str, Enum):
    rich = "rich"
    json = "json"


class ExplainFormat(str, Enum):
    rich = "rich"
    md = "md"
    json = "json"


class Level(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class FailOn(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"
    none = "none"


_DEPTH = typer.Option(DEFAULT_DEPTH, "--depth", min=1, max=MAX_DEPTH,
                      help="Maximum CALLS hops to follow from a handler to the vulnerable function.")
_FORMAT = typer.Option(Format.rich, "--format", "-f", help="Output format.")
_PROJECT = typer.Option(Path("."), "--project", "-p", help="The project folder that was scanned.")


def _console() -> Console:
    return Console(highlight=False, soft_wrap=False)


def _print_json(data: dict) -> None:
    typer.echo(json.dumps(data, indent=2, ensure_ascii=True))


def _fail(message: str) -> None:
    # soft_wrap: one logical line, so a suggested command or a path is never split mid-way
    Console(stderr=True, highlight=False, soft_wrap=True).print(f"[bold red]error:[/] {escape(message)}")
    raise typer.Exit(EXIT_ERROR)


@app.command()
def scan(
    path: Path = typer.Argument(..., help="Project folder to scan."),
    format: Format = _FORMAT,
    min_severity: Level = typer.Option(Level.info, "--min-severity", help="Lowest severity to show."),
    depth: int = _DEPTH,
    fail_on: FailOn = typer.Option(
        FailOn.high, "--fail-on",
        help="Exit 1 when any finding is at or above this severity (the rules' severity; "
             "the model's adjustment never changes the gate)."),
    offline: bool = typer.Option(False, "--offline",
                                 help="Compute reachability in memory; do not write the graph cache (.gittrace/graph.json)."),
    no_blame: bool = typer.Option(False, "--no-blame", help="Skip the git blame owner lookup."),
    include_tests: bool = typer.Option(
        False, "--include-tests",
        help="Treat findings in test code like any other (default: a separate section at info)."),
    model: str = typer.Option(
        None, "--model",
        help="LiteLLM model for triage (default: $GITTRACE_MODEL, else ollama/llama3.1:8b)."),
    no_llm: bool = typer.Option(False, "--no-llm", help="Skip every model call: rule findings only."),
    fix: bool = typer.Option(
        False, "--fix",
        help="Also ask the model for a fix per finding, shown as a diff checked with "
             "git apply --check (never applied). Slower."),
    show_email: bool = typer.Option(False, "--show-email",
                                    help="Show the git blame author's email next to the name."),
) -> None:
    """Scan a Python project: rule findings, attack paths from routes, blast radius, owner,
    and a model's triage of each finding."""
    from gittrace.core.scan import scan as run_scan

    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    if not path.is_dir():
        _fail(f"not a directory: {path}")
    if fix and no_llm:
        _fail("--fix asks the model for fixes; it cannot be combined with --no-llm")
    try:
        result = run_scan(path, depth=depth, blame=not no_blame, offline=offline,
                          include_tests=include_tests)
    except OSError as exc:               # the graph cache could not be written
        _fail(f"{exc} (use --offline to scan without writing the graph cache)")
    triage = llm = None
    if not no_llm:
        triage, llm = _triage(result, result.at_least(min_severity.value), model, fix)
    data = result.to_dict(min_severity.value, triage=triage, llm=llm, show_email=show_email)
    if format is Format.json:
        _print_json(data)
    else:
        functions = {f.id: f for f in result.analysis.functions}
        render.render_scan(_console(), data, functions, blamed=not no_blame)
    if fail_on is not FailOn.none and result.at_least(fail_on.value):
        raise typer.Exit(EXIT_FINDINGS)


def _triage(result, findings, model: str | None, fix: bool) -> tuple[dict, dict]:
    """Ask the model about each finding, with a progress bar on stderr."""
    from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeElapsedColumn

    from gittrace.llm.cache import Cache
    from gittrace.llm.client import LLMError, ModelClient, ModelUnavailable, resolve_model
    from gittrace.llm.triage import triage_findings

    try:
        client = ModelClient(resolve_model(model))
    except LLMError as exc:
        _fail(str(exc))
    stderr = Console(stderr=True, highlight=False)
    try:
        with Progress(TextColumn(f"[{render.LAVENDER}]triage[/] {client.model}"), BarColumn(),
                      MofNCompleteColumn(), TimeElapsedColumn(), console=stderr,
                      transient=True) as bar:
            task = bar.add_task("triage", total=len(findings))
            run = triage_findings(result.analysis, findings, client, Cache(result.root),
                                  progress=lambda i, n, f: bar.update(task, completed=i - 1), fix=fix)
    except ModelUnavailable as exc:
        _fail(f"{exc} Use --no-llm to scan without a model.")
    for t in run.errors:
        stderr.print(Text(f"warning: could not triage {t.finding_id}: {t.error}", style=render.AMBER))
    return run.to_dicts(), run.meta()


def _tool_result(data: dict) -> dict:
    if "error" in data:
        _fail(data["error"])
    return data


def _run_tool(fn, *args):
    try:
        data = fn(*args)
    except RuntimeError as exc:
        _fail(str(exc))
    return _tool_result(data)


@app.command()
def trace(
    target: str = typer.Argument(..., help="file.py:line, or a finding id (file.py::line::col)."),
    project: Path = _PROJECT,
    depth: int = _DEPTH,
    format: Format = _FORMAT,
) -> None:
    """Show the attack paths from endpoints to the finding at file:line."""
    from gittrace.core.tools import trace_attack_path

    data = _run_tool(trace_attack_path, str(project), target, depth)
    if format is Format.json:
        _print_json(data)
    else:
        render.render_trace(_console(), data)


@app.command("blast-radius")
def blast_radius(
    function_id: str = typer.Argument(..., help="Function id, e.g. app/db.py::Repo.get_user."),
    project: Path = _PROJECT,
    depth: int = _DEPTH,
    format: Format = _FORMAT,
) -> None:
    """Show every caller of a function and every endpoint that reaches it."""
    from gittrace.core.tools import blast_radius as run_blast_radius

    data = _run_tool(run_blast_radius, str(project), function_id, depth)
    if format is Format.json:
        _print_json(data)
    else:
        render.render_blast_radius(_console(), data)


@app.command()
def doctor(format: Format = _FORMAT) -> None:
    """Check that this machine is ready: Python, Ollama and its models, free VRAM,
    power and sleep settings. Changes nothing."""
    from gittrace.cli import machine as doc

    checks = doc.run_checks()
    if format is Format.json:
        _print_json(doc.to_json(checks))
    else:
        doc.render_checks(_console(), checks)
    if any(c.status == "fail" for c in checks):
        raise typer.Exit(EXIT_FINDINGS)


@app.command()
def up(pull: bool = typer.Option(False, "--pull", help="Also pull the Ollama models that are missing "
                                                        "(several GB the first time).")) -> None:
    """Check Ollama and the models, and with --pull pull the missing ones."""
    from gittrace.cli import machine as doc

    code = doc.up(_console(), pull=pull)
    if code:
        raise typer.Exit(code)


CONFIRM_ABOVE_S = 600


@app.command()
def explain(
    path: Path = typer.Argument(..., help="Project folder to explain."),
    format: ExplainFormat = typer.Option(None, "--format", "-f",
                                         help="Output format (default rich; with --out, only a short note)."),
    out: Path = typer.Option(None, "--out", "-o", help="Also write the explanation as Markdown to this file."),
    file: str = typer.Option(None, "--file", help="Explain one file (path relative to the project)."),
    function: str = typer.Option(None, "--function", help="Explain one function, by id (path.py::Name)."),
    all_functions: bool = typer.Option(False, "--all",
                                       help="Summarise every function, not only the important ones."),
    min_callers: int = typer.Option(3, "--min-callers", min=1,
                                    help="A function called from at least this many functions is important."),
    depth: int = typer.Option(4, "--depth", min=1, max=10, help="How deep the request-flow trees go."),
    model: str = typer.Option(None, "--model",
                              help="LiteLLM model (default: $GITTRACE_EXPLAIN_MODEL, else "
                                   "ollama/qwen2.5-coder:7b; triage's $GITTRACE_MODEL does not apply)."),
    no_llm: bool = typer.Option(False, "--no-llm", help="Facts only: no model summaries."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Do not ask before a run estimated over 10 minutes."),
) -> None:
    """Explain a Python project in plain language: entry points, endpoints, modules, libraries,
    side effects, request flows, and model-written summaries of files and functions."""
    from gittrace.cli import explain_render
    from gittrace.core import explain as facts
    from gittrace.core.scan import scan as run_scan

    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    if not path.is_dir():
        _fail(f"not a directory: {path}")
    if file and function:
        _fail("--file and --function cannot be combined")
    result = run_scan(path, offline=True, blame=False)        # facts and findings; no graph needed
    ex = facts.build(result, min_callers=min_callers, flow_depth=depth)

    if function:
        if function not in ex.functions or ex.functions[function].is_module:
            near = sorted(f.id for f in ex.summarisable() if function in (f.qualified_name, f.name))
            hint = f" Did you mean: {', '.join(near[:5])}?" if near else ""
            _fail(f"no function with id {function!r} in {path}.{hint} (ids look like app/db.py::Repo.get_user)")
        files, fns, project = [ex.functions[function].file], [function], False
        scope = f"function {function}"
    elif file:
        rel = _project_file(path, file)
        if rel not in ex.files:
            _fail(f"no parsed Python file {file!r} in {path}")
        files, fns, project = [rel], list(ex.files[rel].functions), False
        scope = f"file {rel}"
    else:
        files, project, scope = list(ex.files), True, None
        fns = [f.id for f in (ex.summarisable() if all_functions else ex.important())]

    run = None
    if not no_llm:
        run = _summarise(ex, result.analysis, fns, files if not function else [], project, model, yes)
    data = explain_render.build_data(
        ex, run, files=files, functions=[function] if function else None, project=project,
        settings={"scope": scope, "all": all_functions, "min_callers": min_callers, "flow_depth": depth})
    if out is not None:
        out.write_text(explain_render.to_markdown(data), encoding="utf-8")
    if format is ExplainFormat.json:
        _print_json(data)
    elif format is ExplainFormat.md:
        typer.echo(explain_render.to_markdown(data), nl=False)
    elif format is ExplainFormat.rich or out is None:
        explain_render.render_rich(_console(), data)
    if out is not None:
        Console(stderr=True, highlight=False).print(
            f"wrote {out} ({len(data['files'])} files; {explain_render._llm_line(data['llm'])})")


def _project_file(root: Path, file: str) -> str:
    p = Path(file)
    if p.is_absolute():
        try:
            p = p.resolve().relative_to(root.resolve())
        except ValueError:
            return file
    return p.as_posix().lstrip("./") if p.as_posix().startswith("./") else p.as_posix()


def _summarise(ex, analysis, fns, files, project, model, yes):
    """The model summaries, with an estimate first and a progress bar with ETA."""
    from rich.progress import (BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeElapsedColumn,
                               TimeRemainingColumn)

    from gittrace.llm import explain as summaries
    from gittrace.llm.cache import Cache
    from gittrace.llm.client import LLMError, ModelClient, ModelUnavailable, resolve_explain_model

    try:
        client = ModelClient(resolve_explain_model(model))
    except LLMError as exc:
        _fail(str(exc))
    plan = summaries.plan(ex, fns, files, project)
    estimate = summaries.estimate_seconds(len(plan), client.model)
    stderr = Console(stderr=True, highlight=False)
    stderr.print(f"[{render.LAVENDER}]explain[/] {client.model}: {len(plan)} model calls "
                 f"({len(fns)} functions, {len(files)} files{', the project' if project else ''}), "
                 f"about {estimate / 60:.0f} min at {summaries.seconds_per_call(client.model):g} s per call "
                 "(cached replies take no time)")
    if estimate > CONFIRM_ABOVE_S and not yes:
        if not sys.stdin.isatty():
            _fail(f"estimated {estimate / 60:.0f} minutes; pass --yes to run anyway, or narrow it "
                  "(--file, --function, a higher --min-callers, or --no-llm)")
        if not typer.confirm(f"This may take about {estimate / 60:.0f} minutes. Continue?", default=False):
            raise typer.Exit(0)
    explainer = summaries.Explainer(ex, analysis, client, Cache(ex.root))
    try:
        with Progress(TextColumn(f"[{render.LAVENDER}]explain[/] {{task.description}}"), BarColumn(),
                      MofNCompleteColumn(), TimeElapsedColumn(), TextColumn("ETA"), TimeRemainingColumn(),
                      console=stderr, transient=True) as bar:
            task = bar.add_task("", total=len(plan))

            def progress(i, n, item):
                bar.update(task, completed=i - 1, description=f"{item[0]} {item[1]}"[:60])

            run = explainer.execute(plan, progress)
    except ModelUnavailable as exc:
        _fail(f"{exc} Use --no-llm for the facts without a model.")
    for s in run.summaries.values():
        if s.error:
            stderr.print(Text(f"warning: no summary for {s.level} {s.target}: {s.error}", style=render.AMBER))
    return run


INTERACTIVE_ARGS = ([], ["--no-anim"])


def _interactive(args: list[str]) -> bool:
    """`gittrace` alone (or with --no-anim) in a terminal opens the interactive
    mode; anything else, and any run without a terminal, is the CLI as before."""
    return args in INTERACTIVE_ARGS and sys.stdin.isatty() and sys.stdout.isatty()


def main() -> None:
    # Rich draws box and block characters; a legacy code page (cp1252 on a
    # redirected Windows stdout) cannot encode them and would crash the run.
    for stream in (sys.stdout, sys.stderr):
        if (getattr(stream, "encoding", "") or "").lower().replace("-", "") != "utf8":
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (AttributeError, ValueError):
                pass
    from gittrace import config

    config.load()                       # .env settings (model, timeout, database) for every command
    args = sys.argv[1:]
    try:
        if _interactive(args):
            try:
                from gittrace.cli import interactive
            except ImportError as exc:
                _fail(f"the interactive mode needs Textual ({exc}); pip install -r requirements.txt")
            raise SystemExit(interactive.run(no_anim=bool(args)))
        if args == ["--no-anim"]:
            _fail("--no-anim is for the interactive mode, which needs a terminal (run `gittrace` alone in one)")
    except typer.Exit as exc:           # _fail outside a Typer command
        raise SystemExit(exc.exit_code) from None
    app()


__all__ = ["app", "main", "severity_rank"]
