"""
gittrace.cli — the command line (Typer).

    gittrace scan <path> [--format rich|json] [--min-severity LEVEL] [--depth N]
                         [--fail-on LEVEL|none] [--offline] [--no-blame] [--include-tests]
                         [--model NAME] [--no-llm]
    gittrace trace <file:line | finding-id> [--project PATH] [--depth N] [--format ...]
    gittrace blast-radius <function-id> [--project PATH] [--depth N] [--format ...]

`scan` asks a model (gittrace.llm; --model, else $GITTRACE_MODEL, else
ollama/llama3.1:8b) to triage each finding it shows, unless --no-llm.
Test-code findings are not triaged unless --include-tests.

Exit codes: 0 ok; 1 `scan` found something at or above --fail-on (default
high), so it can gate CI; the gate reads the rules' severity, never the
model's adjustment; 2 an error (bad arguments, no graph, FalkorDB down, the
model cannot be called).

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
from rich.text import Text

from gittrace.cli import render
from gittrace.core.reachability import DEFAULT_DEPTH, MAX_DEPTH
from gittrace.rules.base import severity_rank

app = typer.Typer(add_completion=False, no_args_is_help=True,
                  help="Find vulnerabilities reachable from your API routes.")

EXIT_FINDINGS = 1
EXIT_ERROR = 2


class Format(str, Enum):
    rich = "rich"
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
    Console(stderr=True, highlight=False).print(f"[bold red]error:[/] {message}")
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
                                 help="Compute reachability in memory; do not write the FalkorDB graph."),
    no_blame: bool = typer.Option(False, "--no-blame", help="Skip the git blame owner lookup."),
    include_tests: bool = typer.Option(
        False, "--include-tests",
        help="Treat findings in test code like any other (default: a separate section at info)."),
    model: str = typer.Option(
        None, "--model",
        help="LiteLLM model for triage (default: $GITTRACE_MODEL, else ollama/llama3.1:8b)."),
    no_llm: bool = typer.Option(False, "--no-llm", help="Skip every model call: rule findings only."),
) -> None:
    """Scan a Python project: rule findings, attack paths from routes, blast radius, owner,
    and a model's triage of each finding."""
    from gittrace.core.scan import scan as run_scan

    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    if not path.is_dir():
        _fail(f"not a directory: {path}")
    try:
        result = run_scan(path, depth=depth, blame=not no_blame, offline=offline,
                          include_tests=include_tests)
    except RuntimeError as exc:          # FalkorDB unreachable, misconfigured, ...
        _fail(f"{exc} (use --offline to scan without FalkorDB)")
    triage = llm = None
    if not no_llm:
        triage, llm = _triage(result, result.at_least(min_severity.value), model)
    data = result.to_dict(min_severity.value, triage=triage, llm=llm)
    if format is Format.json:
        _print_json(data)
    else:
        functions = {f.id: f for f in result.analysis.functions}
        render.render_scan(_console(), data, functions, blamed=not no_blame)
    if fail_on is not FailOn.none and result.at_least(fail_on.value):
        raise typer.Exit(EXIT_FINDINGS)


def _triage(result, findings, model: str | None) -> tuple[dict, dict]:
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
                                  progress=lambda i, n, f: bar.update(task, completed=i - 1))
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
    except RuntimeError as exc:          # FalkorDB unreachable or misconfigured
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


def main() -> None:
    # Rich draws box and block characters; a legacy code page (cp1252 on a
    # redirected Windows stdout) cannot encode them and would crash the run.
    for stream in (sys.stdout, sys.stderr):
        if (getattr(stream, "encoding", "") or "").lower().replace("-", "") != "utf8":
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (AttributeError, ValueError):
                pass
    app()


__all__ = ["app", "main", "severity_rank"]
