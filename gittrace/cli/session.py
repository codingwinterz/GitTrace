"""
gittrace.cli.session — the commands of the interactive mode, without Textual.

`parse()` turns a line typed at the prompt into a Command; `Session.run()`
runs it and draws on a Rich console with the same render functions as the
CLI commands. Each command does what its CLI counterpart does with the
default options (a few CLI flags are accepted, see SPECS). Differences that
come from not owning the terminal:

- errors raise CommandError (shown in the output) instead of exiting;
- progress goes to a `status` callback instead of a progress bar on stderr;
- `/explain` never asks: above CONFIRM_ABOVE_S it prints the estimate and
  runs only with --yes.

The interactive mode remembers a current project (the last /scan or
/explain path, else the working directory), which /trace and /blast-radius
use, and a model set with /model for both /scan and /explain (otherwise each
uses its own default, as on the command line).
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from rich.console import Console
from rich.padding import Padding
from rich.table import Table
from rich.text import Text

from gittrace.cli import render
from gittrace.core.reachability import DEFAULT_DEPTH

Status = Callable[[str], None]


class CommandError(Exception):
    """A command that cannot run; the message is shown to the user."""


@dataclass(frozen=True)
class Spec:
    usage: str
    help: str
    min_args: int = 0
    max_args: int = 0
    flags: frozenset[str] = frozenset()

    @property
    def command(self) -> str:
        """The usage without its options: "/scan [path]"."""
        return self.usage.split(" [--", 1)[0]

    @property
    def options(self) -> str:
        """The options part of the usage ("[--offline] [--no-llm] ..."), or ""."""
        return self.usage[len(self.command):].strip()


SPECS: dict[str, Spec] = {
    "/scan": Spec("/scan [path] [--offline] [--no-llm] [--fix] [--include-tests] [--no-blame] "
                  "[--show-email]",
                  "Scan a project: findings, attack paths from routes, blast radius, the model's triage.",
                  0, 1, frozenset({"--offline", "--no-llm", "--fix", "--include-tests", "--no-blame",
                                   "--show-email"})),
    "/explain": Spec("/explain [path] [--no-llm] [--all] [--yes]",
                     "Explain a project in plain language: endpoints, modules, flows, summaries.",
                     0, 1, frozenset({"--no-llm", "--all", "--yes"})),
    "/trace": Spec("/trace <file:line>",
                   "Attack paths from endpoints to the finding at file:line (after a /scan without --offline).",
                   1, 1),
    "/blast-radius": Spec("/blast-radius <function-id>",
                          "Every caller of a function and every endpoint that reaches it (e.g. app/db.py::Repo.get_user).",
                          1, 1),
    "/model": Spec("/model [name | default]",
                   "Show the models, or use one LiteLLM model for /scan and /explain (default: their own defaults).",
                   0, 1),
    "/help": Spec("/help", "List the commands."),
    "/quit": Spec("/quit", "Leave (also ctrl+q)."),
}
ALIASES = {"/exit": "/quit"}
NAMES = tuple(SPECS)
HELP_MIN_DESCRIPTION = 50   # narrower than this, /help puts each description under its command


@dataclass(frozen=True)
class Command:
    name: str
    args: tuple[str, ...] = ()
    flags: frozenset[str] = frozenset()


def _split(line: str) -> list[str]:
    lexer = shlex.shlex(line, posix=True)
    lexer.whitespace_split = True
    lexer.escape = ""                   # keep the backslashes of Windows paths
    return list(lexer)


def parse(line: str) -> Command | None:
    """A typed line as a Command; None for an empty line. Raises CommandError."""
    line = line.strip()
    if not line:
        return None
    try:
        tokens = _split(line)
    except ValueError as exc:           # an unclosed quote
        raise CommandError(f"cannot read the command: {exc}") from None
    head = tokens[0].lower()
    if not head.startswith("/"):
        raise CommandError(f"commands start with a slash, e.g. /{line} (/help lists them)")
    name = ALIASES.get(head, head)
    spec = SPECS.get(name)
    if spec is None:
        raise CommandError(f"unknown command {head} (/help lists them)")
    args: list[str] = []
    flags: set[str] = set()
    for token in tokens[1:]:
        if token.startswith("--"):
            if token not in spec.flags:
                raise CommandError(f"{name} has no option {token}; usage: {spec.usage}")
            flags.add(token)
        else:
            args.append(token)
    if not spec.min_args <= len(args) <= spec.max_args:
        raise CommandError(f"usage: {spec.usage}")
    return Command(name, tuple(args), frozenset(flags))


SAMPLE = "tests/fixtures/sample_app"


def first_hint(project: Path) -> str:
    """What to type first: the bundled sample when the project has it, else the project itself."""
    target = SAMPLE if (project / SAMPLE).is_dir() else "."
    return f"try /scan {target}   (/help lists the commands)"


@dataclass
class Session:
    project: Path = field(default_factory=Path.cwd)
    model: str | None = None

    def scan_model(self) -> str:
        from gittrace.llm.client import resolve_model
        return resolve_model(self.model)

    def explain_model(self) -> str:
        from gittrace.llm.client import resolve_explain_model
        return resolve_explain_model(self.model)

    def run(self, cmd: Command, console: Console, status: Status = lambda _: None) -> None:
        handler = {"/scan": self.scan, "/explain": self.explain, "/trace": self.trace,
                   "/blast-radius": self.blast_radius, "/model": self.set_model, "/help": self.help}[cmd.name]
        handler(cmd, console, status)

    def _project_arg(self, cmd: Command) -> Path:
        path = Path(cmd.args[0]).expanduser() if cmd.args else self.project
        if not path.is_dir():
            raise CommandError(f"not a directory: {path}")
        self.project = path.resolve()
        return self.project

    # -- commands -----------------------------------------------------------

    def help(self, cmd: Command, console: Console, status: Status) -> None:
        # The command column holds the usage without its options (the options go
        # under the description), so it stays as narrow as "/blast-radius
        # <function-id>"; the description column gets the rest of the width.
        command_width = max(len(spec.command) for spec in SPECS.values())
        side_by_side = console.width - command_width - 2 >= HELP_MIN_DESCRIPTION
        table = Table.grid(padding=(0, 2))
        table.add_column(no_wrap=True)
        table.add_column(overflow="fold")
        for spec in SPECS.values():
            command = Text(spec.command, style=f"bold {render.LAVENDER}")   # Text: "[path]" is not markup
            description = Text(spec.help)
            if spec.options:
                description.append(f"\noptions: {spec.options}", style=render.DIM)
            if side_by_side:
                table.add_row(command, description)
            else:                                         # narrow: the description under its command
                console.print(command)
                console.print(Padding(description, (0, 0, 0, 4)))
        if side_by_side:
            console.print(table)
        console.print(Text("Up and down arrows recall earlier commands; the right arrow accepts a suggestion. "
                           f"Current project: {self.project}", style=render.DIM))

    def set_model(self, cmd: Command, console: Console, status: Status) -> None:
        if cmd.args:
            self.model = None if cmd.args[0].lower() == "default" else cmd.args[0]
        console.print(Text.assemble((f"{'/scan':<10}", render.LAVENDER), self.scan_model()))
        console.print(Text.assemble((f"{'/explain':<10}", render.LAVENDER), self.explain_model()))

    def scan(self, cmd: Command, console: Console, status: Status) -> None:
        from gittrace.core.scan import scan as run_scan

        flags = cmd.flags
        if "--fix" in flags and "--no-llm" in flags:
            raise CommandError("--fix asks the model for fixes; it cannot be combined with --no-llm")
        path = self._project_arg(cmd)
        offline, blame = "--offline" in flags, "--no-blame" not in flags
        status(f"scanning {path}")
        try:
            result = run_scan(path, depth=DEFAULT_DEPTH, blame=blame, offline=offline,
                              include_tests="--include-tests" in flags)
        except OSError as exc:          # the graph cache could not be written
            raise CommandError(f"{exc} (add --offline to scan without writing the graph cache)") from None
        triage = llm = None
        if "--no-llm" not in flags:
            triage, llm = self._triage(result, "--fix" in flags, console, status)
        data = result.to_dict("info", triage=triage, llm=llm, show_email="--show-email" in flags)
        functions = {f.id: f for f in result.analysis.functions}
        render.render_scan(console, data, functions, blamed=blame)

    def _triage(self, result, fix: bool, console: Console, status: Status) -> tuple[dict, dict]:
        from gittrace.llm.cache import Cache
        from gittrace.llm.client import LLMError, ModelClient, ModelUnavailable
        from gittrace.llm.triage import triage_findings

        try:
            client = ModelClient(self.scan_model())
        except LLMError as exc:
            raise CommandError(str(exc)) from None
        findings = result.at_least("info")
        status(f"triage {client.model}: 0/{len(findings)}")
        try:
            run = triage_findings(result.analysis, findings, client, Cache(result.root), fix=fix,
                                  progress=lambda i, n, f: status(f"triage {client.model}: {i - 1}/{n}"))
        except ModelUnavailable as exc:
            raise CommandError(f"{exc} Add --no-llm to scan without a model.") from None
        for t in run.errors:
            console.print(Text(f"warning: could not triage {t.finding_id}: {t.error}", style=render.AMBER))
        return run.to_dicts(), run.meta()

    def explain(self, cmd: Command, console: Console, status: Status) -> None:
        from gittrace.cli import explain_render
        from gittrace.core import explain as facts
        from gittrace.core.scan import scan as run_scan

        path = self._project_arg(cmd)
        all_functions = "--all" in cmd.flags
        status(f"reading {path}")
        result = run_scan(path, offline=True, blame=False)
        ex = facts.build(result)
        files = list(ex.files)
        fns = [f.id for f in (ex.summarisable() if all_functions else ex.important())]
        run = None
        if "--no-llm" not in cmd.flags:
            run = self._summarise(ex, result.analysis, fns, files, "--yes" in cmd.flags, console, status)
            if run is None:
                return
        data = explain_render.build_data(
            ex, run, files=files, functions=None, project=True,
            settings={"scope": None, "all": all_functions, "min_callers": facts.DEFAULT_MIN_CALLERS,
                      "flow_depth": facts.DEFAULT_FLOW_DEPTH})
        explain_render.render_rich(console, data)

    def _summarise(self, ex, analysis, fns, files, yes: bool, console: Console, status: Status):
        from gittrace.cli import CONFIRM_ABOVE_S
        from gittrace.llm import explain as summaries
        from gittrace.llm.cache import Cache
        from gittrace.llm.client import LLMError, ModelClient, ModelUnavailable

        try:
            client = ModelClient(self.explain_model())
        except LLMError as exc:
            raise CommandError(str(exc)) from None
        plan = summaries.plan(ex, fns, files, True)
        estimate = summaries.estimate_seconds(len(plan), client.model)
        console.print(f"[{render.LAVENDER}]explain[/] {client.model}: {len(plan)} model calls "
                      f"({len(fns)} functions, {len(files)} files, the project), "
                      f"about {estimate / 60:.0f} min at {summaries.seconds_per_call(client.model):g} s per call "
                      "(cached replies take no time)")
        if estimate > CONFIRM_ABOVE_S and not yes:
            console.print(Text(f"That may take about {estimate / 60:.0f} minutes. Add --yes to run it anyway, "
                               "or --no-llm for the facts only.", style=render.AMBER))
            return None
        explainer = summaries.Explainer(ex, analysis, client, Cache(ex.root))
        try:
            run = explainer.execute(plan, lambda i, n, item: status(f"explain {client.model}: {i - 1}/{n} "
                                                                    f"{item[0]} {item[1]}"[:100]))
        except ModelUnavailable as exc:
            raise CommandError(f"{exc} Add --no-llm for the facts without a model.") from None
        for s in run.summaries.values():
            if s.error:
                console.print(Text(f"warning: no summary for {s.level} {s.target}: {s.error}", style=render.AMBER))
        return run

    def trace(self, cmd: Command, console: Console, status: Status) -> None:
        from gittrace.core.tools import trace_attack_path

        status(f"tracing {cmd.args[0]}")
        render.render_trace(console, self._tool(trace_attack_path, cmd.args[0]))

    def blast_radius(self, cmd: Command, console: Console, status: Status) -> None:
        from gittrace.core.tools import blast_radius

        status(f"blast radius of {cmd.args[0]}")
        render.render_blast_radius(console, self._tool(blast_radius, cmd.args[0]))

    def _tool(self, fn, target: str) -> dict:
        try:
            data = fn(str(self.project), target, DEFAULT_DEPTH)
        except RuntimeError as exc:
            raise CommandError(str(exc)) from None
        if "error" in data:
            raise CommandError(data["error"])
        return data
