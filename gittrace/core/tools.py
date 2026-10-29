"""
gittrace.core.tools — the graph tools: questions about a scanned project.

Each tool takes the project folder that `gittrace scan` was run on, reads that
project's cached graph (gittrace.graph.memstore.GraphStore), and returns a
JSON-ready dict. Failures come back as {"error": ...}, never as exceptions, so
the CLI, the MCP server and the agent can all show them as they are.

    list_findings(project, min_severity, rule_id)
    trace_attack_path(project, finding, depth)    finding: a Sink id or file:line
    blast_radius(project, function_id, depth)
    finding_owner(project, finding)
"""

from __future__ import annotations

import functools
import os
from pathlib import Path
from typing import Any

from gittrace.core.owner import Blamer
from gittrace.core.reachability import DEFAULT_DEPTH, GraphReachability, Reach, check_depth
from gittrace.rules.base import SEVERITIES, severity_rank


class ToolError(Exception):
    pass


def _graph(project: str):
    from gittrace.graph import store
    from gittrace.graph.memstore import GraphStore, StaleCache

    root = Path(project).resolve()
    try:
        graph = GraphStore.load(root)
    except StaleCache as exc:
        if str(exc) == "no graph":
            raise ToolError(f"no graph for {root}; run `gittrace scan {project}` first") from None
        raise ToolError(f"the graph for {root} is out of date ({exc}); "
                        f"run `gittrace scan {project}` again") from None
    return graph, store.graph_name_for(root), root


SHOW_EMAIL_ENV = "GITTRACE_SHOW_EMAIL"


def show_email() -> bool:
    """The owner's email is left out of tool results (MCP, trace, blast-radius)
    unless $GITTRACE_SHOW_EMAIL is 1 / true / yes. The graph keeps it."""
    return os.environ.get(SHOW_EMAIL_ENV, "").strip().lower() in ("1", "true", "yes")


def _owner(author, email, commit, date) -> dict:
    return {"author": author, **({"email": email} if show_email() else {}), "commit": commit, "date": date}


def _finding_summary(props: dict) -> dict:
    owner = None
    if props.get("owner_status") == "committed":
        owner = _owner(props.get("owner_author"), props.get("owner_email"),
                       props.get("owner_commit"), props.get("owner_date"))
    return {
        "id": props["id"],
        "rule_id": props["rule_id"],
        "title": props["title"],
        "severity": props.get("severity"),
        "score": props.get("score"),
        "file": props["file"],
        "line": props["line"],
        "column": props["column"],
        "function": props["function"],
        "callee": props.get("callee") or None,
        "message": props["message"],
        "snippet": props["snippet"],
        "reasons": list(props.get("reasons") or []),
        "reachable": props.get("reachable"),
        "unauthenticated": props.get("unauthenticated"),
        "uncertain": props.get("uncertain"),
        "endpoints": list(props.get("endpoints") or []),
        "blast_radius": props.get("blast_radius"),
        "in_tests": bool(props.get("in_tests")),
        "owner": owner,
    }


def _sort_key(f: dict):
    return (-severity_rank(f["severity"] or "info"), -(f["score"] or 0),
            not f["unauthenticated"], f["file"], f["line"], f["column"], f["rule_id"])


def _reach_dict(reach: Reach) -> dict:
    return {
        "routes": [{
            "endpoint": r.endpoint_id, "method": r.method, "path": r.path,
            "auth_required": r.auth_required, "prefix_resolved": r.prefix_resolved,
            "hops": r.hops, "path_nodes": list(r.nodes),
        } for r in reach.routes],
        "callers": list(reach.callers),
    }


def _find_sinks(graph, root: Path, finding: str) -> list[dict]:
    """A Sink id (`path.py::line::col`) or `path.py:line` -> matching Sink properties."""
    if "::" in finding:
        rows = [s for s in [graph.sink(finding)] if s is not None]
    else:
        file, sep, line = finding.rpartition(":")
        if not sep or not file or not line.strip().isdigit():
            raise ToolError(f"expected a finding id (path.py::line::col) or path.py:line, got {finding!r}")
        path = Path(file)
        if path.is_absolute():
            try:
                file = path.resolve().relative_to(root).as_posix()
            except ValueError as exc:
                raise ToolError(f"{file} is not inside {root}") from exc
        file = file.replace("\\", "/").removeprefix("./")
        rows = graph.sinks_at(file, int(line))
    if not rows:
        raise ToolError(f"no finding at {finding}")
    return rows


def _guard(fn):
    """Turn the tools' expected failures into {"error": ...} results."""
    @functools.wraps(fn)
    def wrapped(*args, **kwargs) -> dict[str, Any]:
        try:
            return fn(*args, **kwargs)
        except (ToolError, ValueError) as exc:
            return {"error": str(exc)}
    return wrapped


@_guard
def list_findings(project: str, min_severity: str = "info", rule_id: str | None = None) -> dict[str, Any]:
    """All findings of the last scan, most severe first."""
    if min_severity not in SEVERITIES:
        raise ToolError(f"min_severity must be one of {', '.join(SEVERITIES)}")
    graph, name, root = _graph(project)
    findings = [_finding_summary(s) for s in graph.sinks()]
    floor = severity_rank(min_severity)
    findings = [f for f in findings
                if severity_rank(f["severity"] or "info") >= floor
                and (rule_id is None or f["rule_id"] == rule_id)]
    findings.sort(key=_sort_key)
    return {"project": str(root), "graph": name, "count": len(findings), "findings": findings}


@_guard
def trace_attack_path(project: str, finding: str, depth: int = DEFAULT_DEPTH) -> dict[str, Any]:
    """Shortest routes from endpoints to a finding, unauthenticated first."""
    check_depth(depth)
    graph, name, root = _graph(project)
    reach = GraphReachability(graph, depth)
    traces = []
    for props in _find_sinks(graph, root, finding):
        summary = _finding_summary(props)
        traces.append({"finding": summary, **_reach_dict(reach.reach(props["function"]))})
    return {"project": str(root), "graph": name, "depth": depth, "traces": traces}


@_guard
def blast_radius(project: str, function_id: str, depth: int = DEFAULT_DEPTH) -> dict[str, Any]:
    """Upstream callers of a function and the endpoints that reach it."""
    check_depth(depth)
    graph, name, root = _graph(project)
    found = graph.function(function_id)
    if found is None:
        raise ToolError(f"no function {function_id!r} in {name} (ids look like app/db.py::Repo.get_user)")
    props, sinks = found
    file, start, end = props.get("file"), props.get("start_line"), props.get("end_line")
    reach = GraphReachability(graph, depth).reach(function_id)
    data = _reach_dict(reach)
    return {
        "project": str(root), "graph": name, "depth": depth, "function": function_id,
        "file": file, "start_line": start, "end_line": end, "sinks": sorted(sinks),
        "caller_count": len(reach.callers), "endpoint_count": len(reach.routes),
        "unauthenticated_endpoints": sum(1 for r in reach.routes if not r.auth_required),
        "total": len(reach.callers) + len(reach.routes),
        **data,
    }


@_guard
def finding_owner(project: str, finding: str) -> dict[str, Any]:
    """Who last changed a finding's line (git blame), when the project is a git repository."""
    graph, name, root = _graph(project)
    owners = []
    for props in _find_sinks(graph, root, finding):
        owner = _finding_summary(props)["owner"]
        status = props.get("owner_status") or "unknown"
        if status == "unknown":             # scanned with --no-blame: ask git now
            found = Blamer(root).blame(props["file"], [props["line"]]).get(props["line"])
            if found is not None:
                status = found.status
                owner = None if found.author is None else _owner(found.author, found.email,
                                                                  found.commit, found.date)
        owners.append({"finding": props["id"], "file": props["file"], "line": props["line"],
                       "status": status, "owner": owner})
    return {"project": str(root), "graph": name, "owners": owners}
