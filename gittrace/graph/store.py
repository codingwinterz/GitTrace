"""
gittrace.graph.store — write a scanned project to its own graph
(gittrace.graph.memstore.GraphStore, cached in <project>/.gittrace/graph.json).

One graph per project (`graph_name_for`), so scans of different projects never
share data. A scan builds the graph from scratch, so a function, file or call
that no longer exists is gone. Nodes and edges are merged on their stable
IDs: re-scanning unchanged code leaves the same nodes, edges and properties;
only `scanned_at` on the Project node moves.

Schema (language-neutral):
  (:Project {id, name, root, scanned_at, ...counts})
  (:File {path, language, sha256, lines})
  (:Function {id, name, qualified_name, file, kind, start_line, end_line,
              source, is_async, resolved: true})
  (:Function {id: "external::<dotted>", name, qualified_name, kind: "external",
              origin, resolved: false})          -- unresolved callees
  (:Endpoint {id, framework, method, path, handler, file, line,
              auth_required, auth_evidence, prefix_resolved})
  (:Sink {id: "path.py::line::col", rule_id, category, title, base_severity,
          file, line, column, end_line, snippet, function, callee, message,
          evidence, param_derived, params, flow_sensitive,
          -- set once reachability is known (write_findings):
          severity, score, reasons, reachable, unauthenticated, uncertain,
          endpoints, endpoint_count, caller_count, blast_radius, in_tests,
          owner_status, owner_author, owner_email, owner_commit, owner_date})
  (File)-[:DECLARES]->(Function|Endpoint)
  (Endpoint)-[:HANDLED_BY]->(Function)
  (Function)-[:CALLS {lines}]->(Function)
  (Function)-[:REACHES_SINK]->(Sink)

One Sink per dangerous call site (or hardcoded-secret assignment), linked from
the function it is in. Findings come from Sink nodes, never from the shared
`external::` callee nodes.
"""

from __future__ import annotations

import hashlib
import os
import re
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from gittrace.languages.base import external_id


def graph_name_for(root: str | os.PathLike) -> str:
    """A stable, readable graph name for a project folder:
    `gittrace_<folder name>_<8 hex of the absolute path>`."""
    resolved = os.path.normcase(str(Path(root).resolve()))
    slug = re.sub(r"[^a-z0-9]+", "_", Path(resolved).name.lower()).strip("_")[:40] or "project"
    digest = hashlib.sha1(resolved.encode("utf-8")).hexdigest()[:8]
    return f"gittrace_{slug}_{digest}"


def write_analysis(graph, analysis, graph_name: str, sinks=()) -> str:
    """Build `graph` (an empty GraphStore) from `analysis` (a
    gittrace.core.pipeline.Analysis) and the rule matches in `sinks`
    (gittrace.rules.base.Match). Returns the scan_id stamped on everything."""
    scan_id = uuid.uuid4().hex
    stamp = {"scan_id": scan_id}

    project = {
        "name": analysis.root.name,
        "root": str(analysis.root),
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        **analysis.counts(),
    }
    graph.merge_node("Project", graph_name, {"id": graph_name, **project, **stamp})

    for f in analysis.files:
        graph.merge_node("File", f.path, {"path": f.path, "language": f.language, "sha256": f.sha256,
                                          "lines": f.lines, **stamp})

    for f in analysis.functions:
        graph.merge_node("Function", f.id, {
            "id": f.id, "name": f.name, "qualified_name": f.qualified_name, "file": f.file,
            "kind": f.kind, "start_line": f.start_line, "end_line": f.end_line,
            "source": f.source, "is_async": f.is_async, "resolved": True, **stamp,
        })
    for f in analysis.functions:
        graph.merge_edge("DECLARES", ("File", f.file), ("Function", f.id), stamp)

    # Unresolved callees: one node per full dotted name. Instantiating a
    # project class with no __init__ runs no project code: no node, no edge.
    externals: dict[str, dict] = {}
    edges: dict[tuple[str, str], set[int]] = defaultdict(set)
    dynamic_edges: set[tuple[str, str]] = set()
    for call in analysis.calls:
        if call.resolved:
            key = (call.caller_id, call.callee_id)
        elif call.origin != "class":
            eid = external_id(call.dotted)
            externals.setdefault(eid, {
                "id": eid, "name": call.dotted.rsplit(".", 1)[-1], "qualified_name": call.dotted,
                "kind": "external", "origin": call.origin, "resolved": False,
            })
            key = (call.caller_id, eid)
        else:
            continue                            # instantiating a class runs no project code
        edges[key].add(call.line)
        if call.dynamic:                       # getattr dispatch: an inferred target set
            dynamic_edges.add(key)
    for eid, props in externals.items():
        graph.merge_node("Function", eid, {**props, **stamp})
    for (a, b), lines in edges.items():
        graph.merge_edge("CALLS", ("Function", a), ("Function", b),
                         {"lines": sorted(lines), "dynamic": (a, b) in dynamic_edges, **stamp})

    for e in analysis.endpoints:
        graph.merge_node("Endpoint", e.id, {
            "id": e.id, "framework": e.framework, "method": e.method, "path": e.path,
            "handler": e.handler_id, "file": e.file, "line": e.line,
            "auth_required": e.auth_required, "auth_evidence": list(e.auth_evidence),
            "prefix_resolved": e.prefix_resolved, **stamp,
        })
    for e in analysis.endpoints:
        graph.merge_edge("DECLARES", ("File", e.file), ("Endpoint", e.id), stamp)
    for e in analysis.endpoints:
        graph.merge_edge("HANDLED_BY", ("Endpoint", e.id), ("Function", e.handler_id), stamp)

    for m in sinks:
        graph.merge_node("Sink", m.sink_id, {
            "id": m.sink_id, "rule_id": m.rule_id, "category": m.category, "title": m.title,
            "base_severity": m.base_severity, "file": m.site.file, "line": m.site.line,
            "column": m.site.column, "end_line": m.site.end_line, "snippet": m.site.snippet,
            "function": m.function_id, "callee": m.callee or "", "message": m.message,
            "evidence": list(m.evidence), "param_derived": m.param_derived,
            "params": list(m.params), "flow_sensitive": m.flow_sensitive, **stamp,
        })
    for m in sinks:
        graph.merge_edge("REACHES_SINK", ("Function", m.function_id), ("Sink", m.sink_id), stamp)
    return scan_id


def write_findings(graph, graph_name: str, findings) -> None:
    """Record the computed severity, reachability and owner on each Sink
    (gittrace.core.scan.Finding), and the totals on the Project node."""
    for f in findings:
        if graph.props("Sink", f.id) is None:
            continue
        owner = f.owner
        graph.merge_node("Sink", f.id, {
            "severity": f.severity, "score": f.score, "reasons": list(f.reasons),
            "reachable": f.reachable, "unauthenticated": f.unauthenticated,
            "uncertain": f.uncertain, "endpoints": [r.endpoint_id for r in f.routes],
            "endpoint_count": len(f.routes), "caller_count": len(f.callers),
            "blast_radius": f.blast_radius, "in_tests": f.in_tests,
            "owner_status": owner.status if owner else "unknown",
            "owner_author": (owner.author if owner else None) or "",
            "owner_email": (owner.email if owner else None) or "",
            "owner_commit": (owner.commit if owner else None) or "",
            "owner_date": (owner.date if owner else None) or "",
        })
    main = [f for f in findings if not f.in_tests]
    by_level = {level: 0 for level in ("critical", "high", "medium", "low", "info")}
    for f in main:
        by_level[f.severity] += 1
    if graph.props("Project", graph_name) is not None:
        graph.merge_node("Project", graph_name, {
            "findings": len(main), "findings_tests": len(findings) - len(main),
            **{f"findings_{k}": v for k, v in by_level.items()},
        })
