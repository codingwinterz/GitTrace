"""
gittrace.graph.store — write a scanned project to its own FalkorDB graph.

One graph per project (`graph_name_for`), so scans of different projects never
share data. A scan rebuilds the graph in place:

  1. every node and edge is written with MERGE on its stable ID and stamped
     with this scan's `scan_id`;
  2. whatever still carries an older stamp — a function, file or call that no
     longer exists — is deleted.

Re-scanning unchanged code therefore leaves the same nodes, edges and
properties; only `scan_id` / `scanned_at` on the Project node move.

Schema (language-neutral):
  (:Project {id, name, root, scanned_at, ...counts})
  (:File {path, language, sha256, lines})
  (:Function {id, name, qualified_name, file, kind, start_line, end_line,
              source, is_async, resolved: true})
  (:Function {id: "external::<dotted>", name, qualified_name, kind: "external",
              origin, resolved: false})          -- unresolved callees
  (:Endpoint {id, framework, method, path, handler, file, line,
              auth_required, auth_evidence, prefix_resolved})
  (File)-[:DECLARES]->(Function|Endpoint)
  (Endpoint)-[:HANDLED_BY]->(Function)
  (Function)-[:CALLS {lines}]->(Function)
"""

from __future__ import annotations

import hashlib
import os
import re
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from gittrace.languages.base import external_id

INDEXES = (("Function", "id"), ("File", "path"), ("Endpoint", "id"))
BATCH = 500


def graph_name_for(root: str | os.PathLike) -> str:
    """A stable, readable graph name for a project folder:
    `gittrace_<folder name>_<8 hex of the absolute path>`."""
    resolved = os.path.normcase(str(Path(root).resolve()))
    slug = re.sub(r"[^a-z0-9]+", "_", Path(resolved).name.lower()).strip("_")[:40] or "project"
    digest = hashlib.sha1(resolved.encode("utf-8")).hexdigest()[:8]
    return f"gittrace_{slug}_{digest}"


def ensure_indexes(graph) -> None:
    rows = graph.query("CALL db.indexes() YIELD label, properties RETURN label, properties").result_set
    existing = {(label, prop) for label, props in rows for prop in props}
    for label, prop in INDEXES:
        if (label, prop) not in existing:
            graph.query(f"CREATE INDEX FOR (n:{label}) ON (n.{prop})")


def _batches(rows: list, size: int = BATCH) -> Iterable[list]:
    for i in range(0, len(rows), size):
        yield rows[i:i + size]


def _write(graph, cypher: str, rows: list, scan_id: str) -> None:
    for chunk in _batches(rows):
        graph.query(cypher, params={"rows": chunk, "scan": scan_id})


def write_analysis(graph, analysis, graph_name: str) -> str:
    """Rebuild `graph` from `analysis` (a gittrace.core.pipeline.Analysis).
    Returns the scan_id."""
    scan_id = uuid.uuid4().hex
    ensure_indexes(graph)

    project = {
        "name": analysis.root.name,
        "root": str(analysis.root),
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        **analysis.counts(),
    }
    graph.query(
        "MERGE (p:Project {id: $id}) SET p += $props, p.scan_id = $scan",
        params={"id": graph_name, "props": project, "scan": scan_id},
    )

    _write(graph, (
        "UNWIND $rows AS r MERGE (f:File {path: r.path}) "
        "SET f.language = r.language, f.sha256 = r.sha256, f.lines = r.lines, f.scan_id = $scan"
    ), [vars(f) for f in analysis.files], scan_id)

    functions = [{
        "id": f.id,
        "file": f.file,
        "props": {
            "name": f.name, "qualified_name": f.qualified_name, "file": f.file,
            "kind": f.kind, "start_line": f.start_line, "end_line": f.end_line,
            "source": f.source, "is_async": f.is_async, "resolved": True,
        },
    } for f in analysis.functions]
    _write(graph, (
        "UNWIND $rows AS r MERGE (fn:Function {id: r.id}) SET fn += r.props, fn.scan_id = $scan"
    ), functions, scan_id)
    _write(graph, (
        "UNWIND $rows AS r MATCH (f:File {path: r.file}) MATCH (fn:Function {id: r.id}) "
        "MERGE (f)-[d:DECLARES]->(fn) SET d.scan_id = $scan"
    ), functions, scan_id)

    # Unresolved callees: one node per full dotted name. Instantiating a
    # project class with no __init__ runs no project code: no node, no edge.
    externals: dict[str, dict] = {}
    edges: dict[tuple[str, str], set[int]] = defaultdict(set)
    for call in analysis.calls:
        if call.resolved:
            edges[(call.caller_id, call.callee_id)].add(call.line)
        elif call.origin != "class":
            eid = external_id(call.dotted)
            externals.setdefault(eid, {
                "id": eid,
                "props": {
                    "name": call.dotted.rsplit(".", 1)[-1], "qualified_name": call.dotted,
                    "kind": "external", "origin": call.origin, "resolved": False,
                },
            })
            edges[(call.caller_id, eid)].add(call.line)
    _write(graph, (
        "UNWIND $rows AS r MERGE (fn:Function {id: r.id}) SET fn += r.props, fn.scan_id = $scan"
    ), list(externals.values()), scan_id)
    _write(graph, (
        "UNWIND $rows AS r MATCH (a:Function {id: r.caller}) MATCH (b:Function {id: r.callee}) "
        "MERGE (a)-[c:CALLS]->(b) SET c.lines = r.lines, c.scan_id = $scan"
    ), [{"caller": a, "callee": b, "lines": sorted(lines)} for (a, b), lines in edges.items()], scan_id)

    endpoints = [{
        "id": e.id,
        "file": e.file,
        "handler": e.handler_id,
        "props": {
            "framework": e.framework, "method": e.method, "path": e.path,
            "handler": e.handler_id, "file": e.file, "line": e.line,
            "auth_required": e.auth_required, "auth_evidence": list(e.auth_evidence),
            "prefix_resolved": e.prefix_resolved,
        },
    } for e in analysis.endpoints]
    _write(graph, (
        "UNWIND $rows AS r MERGE (e:Endpoint {id: r.id}) SET e += r.props, e.scan_id = $scan"
    ), endpoints, scan_id)
    _write(graph, (
        "UNWIND $rows AS r MATCH (f:File {path: r.file}) MATCH (e:Endpoint {id: r.id}) "
        "MERGE (f)-[d:DECLARES]->(e) SET d.scan_id = $scan"
    ), endpoints, scan_id)
    _write(graph, (
        "UNWIND $rows AS r MATCH (e:Endpoint {id: r.id}) MATCH (fn:Function {id: r.handler}) "
        "MERGE (e)-[h:HANDLED_BY]->(fn) SET h.scan_id = $scan"
    ), endpoints, scan_id)

    # Drop what this scan did not write: edges first (between surviving
    # nodes), then nodes, which takes their remaining edges with them.
    graph.query("MATCH ()-[r]->() WHERE r.scan_id IS NULL OR r.scan_id <> $scan DELETE r",
                params={"scan": scan_id})
    graph.query("MATCH (n) WHERE n.scan_id IS NULL OR n.scan_id <> $scan DETACH DELETE n",
                params={"scan": scan_id})
    return scan_id
