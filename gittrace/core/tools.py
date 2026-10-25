"""
gittrace.core.tools — the FalkorDB-backed graph tools.

  - get_blast_radius(cve_id)
  - find_shortest_dependency_path(start_service, target_function,
                                  *, target_file_path=None, cve_id=None)
  - find_code_owner(function_name, *, file_path=None, cve_id=None)

The falkordb 1.8.0 API used here:
    db.select_graph(name) -> Graph
    graph.query(cypher, params) -> QueryResult
    QueryResult.result_set -> list of row-lists

shortestPath is only supported in WITH or RETURN clauses in FalkorDB
(not directly in MATCH), so the Cypher below uses WITH ... shortestPath ... AS p.

Function names are not unique (validate_token and refresh_token exist in two
services), so a Function is only ever identified by its (file path, name)
pair, or through a CVE's AFFECTS edge. Results carry that pair as
"file_path::name" wherever a bare name would be ambiguous.
"""

from __future__ import annotations

from typing import Any

from gittrace.graph import connection


def _qualified(file_path: str, function_name: str) -> str:
    return f"{file_path}::{function_name}"


def _function_files(g, function_name: str) -> list[str]:
    """Paths of every File that defines a Function with exactly this name."""
    rows = g.query(
        "MATCH (file:File)-[:DEFINES]->(f:Function {name: $name}) "
        "RETURN DISTINCT file.path AS path ORDER BY path",
        params={"name": function_name},
    ).result_set
    return [str(r[0]) for r in rows if r and r[0]]


def _ambiguous_error(function_name: str, file_paths: list[str]) -> str:
    return (
        f"'{function_name}' is defined in {len(file_paths)} files "
        f"({', '.join(file_paths)}). Pass file_path or cve_id to pick one."
    )


def get_blast_radius(cve_id: str) -> dict[str, Any]:
    """Find every function that can reach the code a CVE affects, and the
    services those callers live in.

    The blast radius is upstream: if the vulnerable function is exploited or
    taken offline, the functions that call it (directly or transitively) are
    the ones that break or carry the attack further. What the vulnerable
    function itself calls is not at risk from it.

    Cypher:
        MATCH (c:CVE {id: $cve_id})-[:AFFECTS]->(f:Function)<-[:DEFINES]-(file:File)
        OPTIONAL MATCH (caller:Function)-[:CALLS*1..5]->(f) WHERE caller <> f
        OPTIONAL MATCH (caller)<-[:DEFINES]-(caller_file:File)
        OPTIONAL MATCH (caller_file)<-[:CONTAINS]-(s:Service)
        RETURN ... collect(DISTINCT s.name), collect(DISTINCT caller.name) ...
    """
    g = connection.get_graph()

    cypher = """
    MATCH (c:CVE {id: $cve_id})-[:AFFECTS]->(f:Function)<-[:DEFINES]-(file:File)
    OPTIONAL MATCH (caller:Function)-[:CALLS*1..5]->(f)
    WHERE caller <> f
    OPTIONAL MATCH (caller)<-[:DEFINES]-(caller_file:File)
    OPTIONAL MATCH (caller_file)<-[:CONTAINS]-(s:Service)
    RETURN
        c.id AS cve_id,
        c.severity AS severity,
        collect(DISTINCT s.name) AS impacted_services,
        collect(DISTINCT caller.name) AS impacted_functions,
        count(DISTINCT s) AS service_count,
        collect(DISTINCT file.path + '::' + f.name) AS affected_function_ids,
        collect(DISTINCT caller_file.path + '::' + caller.name) AS impacted_function_ids
    """
    result = g.query(cypher, params={"cve_id": cve_id})
    rs = result.result_set
    if not rs:
        return {
            "cve_id": cve_id, "severity": None,
            "affected_function_ids": [],
            "impacted_services": [], "impacted_functions": [],
            "impacted_function_ids": [],
            "service_count": 0,
            "error": f"CVE '{cve_id}' not found in the graph.",
        }

    row = rs[0]

    def _sorted(values) -> list[str]:
        # collect() returns rows in graph-traversal order, which FalkorDB does
        # not guarantee to be stable. Sort so the contract is deterministic.
        return sorted(str(x) for x in (values or []) if x)

    return {
        "cve_id": str(row[0]) if row[0] else cve_id,
        "severity": str(row[1]) if row[1] else None,
        "affected_function_ids": _sorted(row[5]),
        "impacted_services": _sorted(row[2]),
        "impacted_functions": _sorted(row[3]),
        "impacted_function_ids": _sorted(row[6]),
        "service_count": int(row[4]) if row[4] is not None else 0,
    }


def find_shortest_dependency_path(
    start_service: str,
    target_function: str,
    *,
    target_file_path: str | None = None,
    cve_id: str | None = None,
) -> dict[str, Any]:
    """Use FalkorDB's native shortestPath (via WITH) to trace how an
    attacker reaches the vulnerable code from a public-facing service.

    The target is scoped to a single Function *instance*, not any function
    sharing its name. If `cve_id` is supplied, the tool derives the exact
    affected Function node from the CVE's AFFECTS edge — the same source
    get_blast_radius uses — so the attack-path and blast-radius tools are
    guaranteed to point at the same vulnerable code. If `target_file_path`
    is supplied, the query matches the Function defined by that file.

    With neither, the name must identify exactly one Function in the graph.
    A name defined in several files (validate_token) is reported as
    ambiguous, with the candidate files, instead of silently resolving to
    whichever copy happens to be closest.

    Implementation note: FalkorDB only supports shortestPath in WITH or
    RETURN clauses, so the Cypher uses WITH ... shortestPath ... AS p.
    The path must traverse CONTAINS (Service->File), DEFINES (File->
    Function), DEPENDS_ON (Service->Service) because a Function lives
    inside a File inside a Service, and services depend on other services.
    """
    g = connection.get_graph()

    def _no_path(reason: str, **extra: Any) -> dict[str, Any]:
        return {
            "start_service": start_service,
            "target_function": target_function,
            "target_file_path": target_file_path,
            "path_trace": [], "hop_count": None,
            "cve_id": cve_id,
            "error": reason,
            **extra,
        }

    if not cve_id and not target_file_path:
        files = _function_files(g, target_function)
        if not files:
            return _no_path(f"Function '{target_function}' not found in the graph.")
        if len(files) > 1:
            return _no_path(
                _ambiguous_error(target_function, files),
                candidates=[_qualified(p, target_function) for p in files],
            )
        target_file_path = files[0]

    if cve_id:
        # Derive the exact affected Function node from the CVE's AFFECTS edge,
        # the same relationship get_blast_radius already uses. This is the
        # recommended way to call the tool for a CVE-driven question: it
        # guarantees the path ends at the precise instance the vulnerability
        # touches (e.g. token-service.validate_token, not auth-service
        # .validate_token).
        cypher = """
        MATCH (c:CVE {id: $cve_id})-[:AFFECTS]->(f:Function)<-[:DEFINES]-(file:File)
        MATCH (s:Service {name: $start_service, is_public: true})
        WITH s, f, file, shortestPath((s)-[:CONTAINS|DEFINES|DEPENDS_ON*1..10]->(f)) AS p
        RETURN
            [n IN nodes(p) | labels(n)[0] + ':' + coalesce(n.name, n.path, n.id)] AS path_trace,
            length(p) AS hop_count,
            file.path AS file_path
        ORDER BY hop_count ASC, path_trace ASC
        LIMIT 1
        """
        result = g.query(cypher, params={
            "start_service": start_service,
            "cve_id": cve_id,
        })
    else:
        cypher = """
        MATCH (s:Service {name: $start_service, is_public: true})
        MATCH (file:File {path: $target_file_path})-[:DEFINES]->(f:Function {name: $target_function})
        WITH s, f, file, shortestPath((s)-[:CONTAINS|DEFINES|DEPENDS_ON*1..10]->(f)) AS p
        RETURN
            [n IN nodes(p) | labels(n)[0] + ':' + coalesce(n.name, n.path, n.id)] AS path_trace,
            length(p) AS hop_count,
            file.path AS file_path
        ORDER BY hop_count ASC, path_trace ASC
        LIMIT 1
        """
        result = g.query(cypher, params={
            "start_service": start_service,
            "target_function": target_function,
            "target_file_path": target_file_path,
        })
    rs = result.result_set
    if not rs:
        return _no_path(
            f"No public path from '{start_service}' to '"
            f"{target_function}'. Either the start service isn't "
            f"public, the function doesn't exist, or there's no "
            f"CONTAINS/DEFINES/DEPENDS_ON path between them."
        )

    row = rs[0]
    raw_trace = row[0]
    if raw_trace is None:
        return {**_no_path("shortestPath returned no nodes."), "hop_count": 0}
    path_trace = [str(item) for item in raw_trace if item]
    # When the query was scoped by CVE, report the Function that the graph
    # actually resolved to (the last node in path_trace) instead of echoing
    # back whatever target_function the caller passed in. That keeps
    # attack_path.target_function consistent with path_trace, e.g. when a
    # different CVE affects get_user_profile rather than validate_token.
    if cve_id and path_trace:
        last_node = path_trace[-1]
        if last_node.startswith("Function:"):
            target_function = last_node[len("Function:"):]
    return {
        "start_service": start_service,
        "target_function": target_function,
        "target_file_path": str(row[2]) if row[2] else target_file_path,
        "path_trace": path_trace,
        "hop_count": int(row[1]) if row[1] is not None else len(path_trace),
        "cve_id": cve_id,
    }


def find_code_owner(
    function_name: str,
    *,
    file_path: str | None = None,
    cve_id: str | None = None,
) -> dict[str, Any]:
    """Find the developer who authored the vulnerable code, for alerting.

    The Function is resolved exactly: through the CVE's AFFECTS edge when
    `cve_id` is given, by (file_path, function_name) when `file_path` is
    given, and otherwise by name only when that name is defined in exactly
    one file. Every matching row is returned and checked, so an ambiguous
    name is reported instead of answered with an arbitrary LIMIT 1 pick.

    Cypher (name-scoped form):
        MATCH (file:File)-[:DEFINES]->(f:Function {name: $function_name})
        OPTIONAL MATCH (file)<-[:AUTHORED]-(dev:Developer)
        OPTIONAL MATCH (dev)-[:OWNS]->(s:Service)
        RETURN file.path, f.name, dev.name, dev.email, dev.slack_handle,
               collect(DISTINCT s.name)
        ORDER BY file_path, function_name, developer_name
    """
    g = connection.get_graph()

    if cve_id:
        match = "MATCH (:CVE {id: $cve_id})-[:AFFECTS]->(f:Function)<-[:DEFINES]-(file:File)"
    elif file_path:
        match = "MATCH (file:File {path: $file_path})-[:DEFINES]->(f:Function {name: $function_name})"
    else:
        match = "MATCH (file:File)-[:DEFINES]->(f:Function {name: $function_name})"

    cypher = match + """
    OPTIONAL MATCH (file)<-[:AUTHORED]-(dev:Developer)
    OPTIONAL MATCH (dev)-[:OWNS]->(s:Service)
    RETURN
        file.path AS file_path,
        f.name AS function_name,
        dev.name AS developer_name,
        dev.email AS email,
        dev.slack_handle AS slack,
        collect(DISTINCT s.name) AS owned_services
    ORDER BY file_path, function_name, developer_name
    """
    result = g.query(cypher, params={
        "function_name": function_name,
        "file_path": file_path,
        "cve_id": cve_id,
    })
    rs = result.result_set

    def _missing(reason: str, **extra: Any) -> dict[str, Any]:
        return {
            "function_name": function_name, "file_path": file_path,
            "developer_name": None, "email": None, "slack": None,
            "owned_services": [], "owners": [],
            "error": reason,
            **extra,
        }

    if not rs:
        return _missing(f"No owner found for function '{function_name}'.")

    targets = sorted({(str(r[0]), str(r[1])) for r in rs})
    if len(targets) > 1:
        names = sorted({name for _, name in targets})
        label = names[0] if len(names) == 1 else function_name
        return _missing(
            _ambiguous_error(label, [path for path, _ in targets]),
            candidates=[_qualified(path, name) for path, name in targets],
        )

    resolved_path, resolved_name = targets[0]
    owners = [
        {
            "developer_name": str(r[2]),
            "email": str(r[3]) if r[3] else None,
            "slack": str(r[4]) if r[4] else None,
            # Sorted for the same reason as the blast-radius lists above.
            "owned_services": sorted(str(x) for x in (r[5] or []) if x),
        }
        for r in rs if r[2]
    ]
    if not owners:
        return {
            **_missing(f"No owner found for function '{resolved_name}' "
                       f"in {resolved_path}."),
            "function_name": resolved_name, "file_path": resolved_path,
        }

    return {
        "function_name": resolved_name,
        "file_path": resolved_path,
        **owners[0],
        "owners": owners,
    }
