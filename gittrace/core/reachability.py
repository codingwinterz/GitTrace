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
  GraphReachability   — the project's graph (gittrace.graph.memstore.GraphStore):
                        a bounded reverse BFS over CALLS edges for the callers,
                        then one shortest path from each candidate endpoint.
  MemoryReachability  — the same bounded BFS over the in-memory analysis, for
                        `gittrace scan --offline` and the offline tests.
When several shortest paths tie, both pick the one through the smallest ids.
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
        if self.graph.props("Function", function_id) is None:
            result = Reach(function_id, (), ())
            self._cache[function_id] = result
            return result
        dist = {function_id: 0}
        frontier = [function_id]
        for d in range(1, self.depth + 1):
            nxt = sorted({c for f in frontier for c in self.graph.callers_of(f)} - dist.keys())
            for c in nxt:
                dist[c] = d
            frontier = nxt
        routes = []
        for handler, hops in dist.items():
            for e in self.graph.endpoints_handled_by(handler):
                nodes = [e["id"], handler]
                cur = handler
                while cur != function_id:
                    cur = min(n for n in self.graph.callees_of(cur) if dist.get(n) == dist[cur] - 1)
                    nodes.append(cur)
                routes.append(Route(e["id"], e["method"], e["path"], bool(e["auth_required"]),
                                    bool(e["prefix_resolved"]), hops, tuple(nodes)))
        callers = tuple(sorted(k for k in dist if k != function_id))
        result = Reach(function_id, callers, _ordered(routes))
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
