"""
gittrace.core.reachability — who can reach a function, and from which routes.

For a vulnerable function F and a depth D (default 10):
  callers — every function with a path of 1..D CALLS edges to F (its blast
            radius upstream), excluding F itself;
  routes  — every Endpoint whose handler is F or one of those callers, each
            with one shortest path Endpoint -HANDLED_BY-> handler -CALLS*-> F.
            `hops` counts the CALLS edges on it (0 when F is the handler).
Routes are ordered unauthenticated first, then by hops, then by endpoint id.

Two backends answer the same question:
  GraphReachability   — Cypher against the project's FalkorDB graph: a bounded
                        variable-length query for the callers, then FalkorDB's
                        native shortestPath from each candidate endpoint.
  MemoryReachability  — the same bounded BFS over the in-memory analysis, for
                        `gittrace scan --offline` and the offline tests. When
                        several shortest paths tie it picks the one through
                        the smallest ids, which may differ from FalkorDB's pick.
"""

from __future__ import annotations

from dataclasses import dataclass

DEFAULT_DEPTH = 10
MAX_DEPTH = 50


@dataclass(frozen=True)
class Route:
    endpoint_id: str
    method: str
    path: str
    auth_required: bool
    prefix_resolved: bool
    hops: int
    nodes: tuple[str, ...]        # endpoint id, handler id, ..., function id


@dataclass(frozen=True)
class Reach:
    function_id: str
    callers: tuple[str, ...]
    routes: tuple[Route, ...]


def check_depth(depth: int) -> int:
    if not isinstance(depth, int) or isinstance(depth, bool) or not 1 <= depth <= MAX_DEPTH:
        raise ValueError(f"depth must be an integer from 1 to {MAX_DEPTH}, got {depth!r}")
    return depth


def _ordered(routes) -> tuple[Route, ...]:
    return tuple(sorted(routes, key=lambda r: (r.auth_required, r.hops, r.endpoint_id)))


class GraphReachability:
    def __init__(self, graph, depth: int = DEFAULT_DEPTH):
        self.graph = graph
        self.depth = check_depth(depth)
        self._cache: dict[str, Reach] = {}

    def reach(self, function_id: str) -> Reach:
        if function_id in self._cache:
            return self._cache[function_id]
        d = self.depth          # validated int: safe to place in the pattern
        callers = self.graph.query(
            f"MATCH (c:Function)-[:CALLS*1..{d}]->(f:Function {{id: $id}}) "
            "WHERE c.id <> $id RETURN DISTINCT c.id ORDER BY c.id",
            params={"id": function_id},
        ).result_set
        rows = self.graph.query(
            "MATCH (f:Function {id: $id}) "
            f"OPTIONAL MATCH (c:Function)-[:CALLS*1..{d}]->(f) "
            "WITH f, collect(DISTINCT c) + [f] AS handlers "
            "UNWIND handlers AS h "
            "MATCH (e:Endpoint)-[:HANDLED_BY]->(h) "
            "WITH DISTINCT e, f "
            f"WITH e, shortestPath((e)-[:HANDLED_BY|CALLS*1..{d + 1}]->(f)) AS p "
            "WHERE p IS NOT NULL "
            "RETURN e.id, e.method, e.path, e.auth_required, e.prefix_resolved, "
            "[n IN nodes(p) | n.id]",
            params={"id": function_id},
        ).result_set
        routes = [
            Route(eid, method, path, bool(auth), bool(resolved), len(nodes) - 2, tuple(nodes))
            for eid, method, path, auth, resolved, nodes in rows
        ]
        result = Reach(function_id, tuple(r[0] for r in callers), _ordered(routes))
        self._cache[function_id] = result
        return result


class MemoryReachability:
    def __init__(self, analysis, depth: int = DEFAULT_DEPTH):
        self.depth = check_depth(depth)
        self.callers_of: dict[str, set[str]] = {}
        for call in analysis.calls:
            if call.resolved:
                self.callers_of.setdefault(call.callee_id, set()).add(call.caller_id)
        self.endpoints_by_handler: dict[str, list] = {}
        for e in analysis.endpoints:
            self.endpoints_by_handler.setdefault(e.handler_id, []).append(e)
        self._cache: dict[str, Reach] = {}

    def reach(self, function_id: str) -> Reach:
        if function_id in self._cache:
            return self._cache[function_id]
        dist = {function_id: 0}
        frontier = [function_id]
        for d in range(1, self.depth + 1):
            nxt = sorted({c for f in frontier for c in self.callers_of.get(f, ())} - dist.keys())
            for c in nxt:
                dist[c] = d
            frontier = nxt
        routes = []
        for handler, hops in dist.items():
            for e in self.endpoints_by_handler.get(handler, ()):
                nodes = [e.id, handler]
                cur = handler
                while cur != function_id:
                    cur = min(n for n, k in dist.items()
                              if k == dist[cur] - 1 and cur in self.callers_of.get(n, ()))
                    nodes.append(cur)
                routes.append(Route(e.id, e.method, e.path, e.auth_required,
                                    e.prefix_resolved, hops, tuple(nodes)))
        callers = tuple(sorted(k for k in dist if k != function_id))
        result = Reach(function_id, callers, _ordered(routes))
        self._cache[function_id] = result
        return result
