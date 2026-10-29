"""
tests/test_memstore.py — the in-process graph store (gittrace.graph.memstore)
and GraphReachability on it:

  1. reachability: depth limits, cycles, self-calls, ties, the d+1 route bound
  2. MERGE semantics: no edge without both nodes, one edge type per node pair
  3. the cache: atomic writes, invalidated by any changed, added or removed
     source file, never served stale, and no raw secret or source in it
"""

from __future__ import annotations

import json
import re
import shutil

import pytest

import expected_sample_app
from gittrace.core import tools
from gittrace.core.reachability import GraphReachability
from gittrace.core.scan import scan
from gittrace.graph import memstore
from gittrace.graph.memstore import CACHE_FILE, GraphStore, StaleCache

ROOT = expected_sample_app.ROOT


def _graph(calls: list[tuple[str, str]], endpoints: dict[str, tuple[str, bool]] = ()) -> GraphStore:
    """Functions named by the calls; endpoints {id: (handler, auth_required)}."""
    g = GraphStore("t")
    for f in sorted({x for pair in calls for x in pair} | {h for h, _ in dict(endpoints).values()}):
        g.merge_node("Function", f, {"id": f, "resolved": True})
    for a, b in calls:
        g.merge_edge("CALLS", ("Function", a), ("Function", b), {"lines": [1]})
    for eid, (handler, auth) in dict(endpoints).items():
        g.merge_node("Endpoint", eid, {"id": eid, "method": "GET", "path": "/" + eid,
                                       "auth_required": auth, "prefix_resolved": True})
        g.merge_edge("HANDLED_BY", ("Endpoint", eid), ("Function", handler))
    return g


class TestReachability:
    def test_callers_stop_at_the_depth(self):
        g = _graph([("a", "b"), ("b", "c"), ("c", "d")], {"e": ("a", False)})
        assert GraphReachability(g, 1).reach("d").callers == ("c",)
        assert GraphReachability(g, 2).reach("d").callers == ("b", "c")
        assert GraphReachability(g, 2).reach("d").routes == ()            # a is 3 hops away
        (route,) = GraphReachability(g, 3).reach("d").routes
        assert route.nodes == ("e", "a", "b", "c", "d") and route.hops == 3

    def test_a_cycle_back_to_the_function_is_not_a_caller(self):
        g = _graph([("a", "b"), ("b", "c"), ("c", "a"), ("c", "c")], {"e": ("c", True)})
        reach = GraphReachability(g, 10).reach("a")
        assert reach.callers == ("b", "c")
        (route,) = reach.routes
        assert route.nodes == ("e", "c", "a") and route.hops == 1

    def test_the_handler_itself(self):
        g = _graph([("a", "a")], {"e": ("a", False)})
        reach = GraphReachability(g, 1).reach("a")
        assert reach.callers == ()
        assert [(r.nodes, r.hops) for r in reach.routes] == [(("e", "a"), 0)]

    def test_ties_take_the_smallest_ids(self):
        g = _graph([("h", "y"), ("h", "x"), ("x", "f"), ("y", "f")], {"e": ("h", False)})
        assert GraphReachability(g, 5).reach("f").routes[0].nodes == ("e", "h", "x", "f")

    def test_one_route_per_endpoint_unauthenticated_first(self):
        g = _graph([("a", "f"), ("b", "c"), ("c", "f")], {"e2": ("a", True), "e1": ("b", False)})
        routes = GraphReachability(g, 5).reach("f").routes
        assert [(r.endpoint_id, r.auth_required, r.hops) for r in routes] == [("e1", False, 2), ("e2", True, 1)]

    def test_unknown_function(self):
        reach = GraphReachability(_graph([("a", "b")]), 5).reach("nope")
        assert reach.callers == () and reach.routes == ()

    def test_matches_the_in_memory_backend_on_the_sample(self):
        from gittrace.core import pipeline
        from gittrace.core.reachability import MemoryReachability

        g = GraphStore("t")
        analysis, _ = pipeline.ingest(ROOT, graph=g, graph_name=g.name)
        memory = MemoryReachability(analysis, 10)
        graph = GraphReachability(g, 10)
        for f in analysis.functions:
            assert graph.reach(f.id) == memory.reach(f.id), f.id


class TestMerge:
    def test_no_edge_without_both_nodes(self):
        g = GraphStore("t")
        g.merge_node("Function", "a", {"id": "a"})
        g.merge_edge("CALLS", ("Function", "a"), ("Function", "missing"))
        g.merge_edge("REACHES_SINK", ("Function", "a"), ("Sink", "s"))
        assert g.g.number_of_edges() == 0

    def test_labels_have_their_own_key_spaces(self):
        g = GraphStore("t")
        g.merge_node("File", "same", {"path": "same"})
        g.merge_node("Function", "same", {"id": "same"})
        assert g.g.number_of_nodes() == 2

    def test_properties_merge_in_place(self):
        g = GraphStore("t")
        g.merge_node("Sink", "s", {"id": "s", "line": 1})
        g.merge_node("Sink", "s", {"severity": "high"})
        assert g.sink("s") == {"id": "s", "line": 1, "severity": "high"}

    def test_a_second_edge_type_between_the_same_nodes_is_refused(self):
        g = GraphStore("t")
        g.merge_node("Function", "a", {})
        g.merge_node("Function", "b", {})
        g.merge_edge("CALLS", ("Function", "a"), ("Function", "b"))
        g.g.edges[("Function", "a"), ("Function", "b")]["type"] = "OTHER"
        with pytest.raises(ValueError, match="already has"):
            g.merge_edge("CALLS", ("Function", "a"), ("Function", "b"))


@pytest.fixture
def project(tmp_path):
    copy = tmp_path / "sample_app"
    shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns(".gittrace"))
    scan(copy, blame=False)
    return copy


class TestCache:
    def test_round_trip(self, project):
        g = GraphStore.load(project)
        assert len(g.sinks()) == 13
        assert tools.list_findings(str(project))["count"] == 13
        assert list((project / ".gittrace").glob("*.tmp")) == []               # written by rename
        assert (project / ".gittrace" / ".gitignore").read_text(encoding="utf-8").endswith("*\n")

    @pytest.mark.parametrize("change", ["edit", "add", "remove"])
    def test_any_file_change_invalidates_it(self, project, change):
        target = project / "app" / "db.py"
        if change == "edit":
            target.write_bytes(target.read_bytes() + b"\n")
        elif change == "add":
            (project / "app" / "extra.py").write_text("X = 1\n", encoding="utf-8")
        else:
            target.unlink()
        with pytest.raises(StaleCache, match="changed since the last scan"):
            GraphStore.load(project)
        out = tools.list_findings(str(project))
        assert "out of date" in out["error"] and "gittrace scan" in out["error"]

    def test_no_cache_and_a_broken_cache(self, project):
        (project / CACHE_FILE).write_text("{not json", encoding="utf-8")
        with pytest.raises(StaleCache, match="unreadable"):
            GraphStore.load(project)
        (project / CACHE_FILE).unlink()
        assert "run `gittrace scan" in tools.list_findings(str(project))["error"]

    def test_a_failed_write_keeps_the_old_cache(self, project, monkeypatch):
        before = (project / CACHE_FILE).read_bytes()

        def broken(*args, **kwargs):
            raise OSError("disk full")
        monkeypatch.setattr(memstore.json, "dump", broken)
        with pytest.raises(OSError, match="disk full"):
            GraphStore.load(project).save(project)
        assert (project / CACHE_FILE).read_bytes() == before
        assert list((project / ".gittrace").glob("*.tmp")) == []

    def test_no_raw_secret_or_source_in_the_cache(self, project):
        text = (project / CACHE_FILE).read_text(encoding="utf-8")
        secrets = []
        for s in GraphStore.load(project).sinks():
            if s["rule_id"].startswith("GT-SECRET"):
                line = (project / s["file"]).read_text(encoding="utf-8").splitlines()[s["line"] - 1]
                secrets.append(re.search(r"=\s*[\"']([^\"']+)[\"']", line).group(1))
        assert len(secrets) == 3
        for value in secrets:
            assert value not in text
        data = json.loads(text)
        assert not [p for label, _, p in data["nodes"] if "source" in p]
