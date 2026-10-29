"""
test_ingest_integration.py — Python ingestion into the real graph store
(gittrace.graph.memstore.GraphStore) and its cache.

Ingests tests/fixtures/sample_app into a graph and checks the exact nodes and
edges (expected values in tests/expected_sample_app.py), then re-scans for
idempotency, edits a copy of the project to check that stale nodes are
removed from the cached graph, and ingests a second project to check
isolation. Tests that write a cache work on a copy in a temporary folder.

    pytest tests/test_ingest_integration.py -v
"""

from __future__ import annotations

import hashlib
import shutil
import uuid
from pathlib import Path

import pytest

import expected_sample_app as expected
from gittrace.core import pipeline
from gittrace.graph import store
from gittrace.graph.memstore import GraphStore

FLASK_ROOT = Path(__file__).resolve().parent / "fixtures" / "flask_app"


def _name() -> str:
    return f"gittrace_test_ingest_{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="module")
def sample_graph():
    g = GraphStore(_name())
    analysis, _ = pipeline.ingest(expected.ROOT, graph=g, graph_name=g.name)
    return g, analysis


def _nodes(g: GraphStore, label: str) -> list[dict]:
    return g.nodes(label)


def _edges(g: GraphStore, type_: str) -> list[tuple]:
    """(source label, source key, target label, target key, props) per edge of `type_`."""
    return [(a[0], a[1], b[0], b[1], d["props"]) for a, b, d in g.g.edges(data=True) if d["type"] == type_]


def _snapshot(g: GraphStore) -> tuple[set, set]:
    """Every node and edge with its properties, minus the per-scan stamps."""
    volatile = {"scan_id", "scanned_at"}

    def clean(props: dict) -> tuple:
        return tuple(sorted((k, repr(v)) for k, v in props.items() if k not in volatile))

    nodes = {(n[0], clean(d["props"])) for n, d in g.g.nodes(data=True)}
    edges = {(a[1], d["type"], b[1], clean(d["props"])) for a, b, d in g.g.edges(data=True)}
    return nodes, edges


def _count(g: GraphStore, label: str, **where) -> int:
    return sum(1 for p in _nodes(g, label) if all(p.get(k) == v for k, v in where.items()))


class TestSampleAppGraph:
    def test_node_counts_by_label(self, sample_graph):
        g, _ = sample_graph
        counts: dict[str, int] = {}
        for label, _key in g.g.nodes:
            counts[label] = counts.get(label, 0) + 1
        externals = {dotted for _, dotted, _, _ in expected.UNRESOLVED}
        assert counts == {
            "Project": 1,
            "File": len(expected.FILES),
            "Function": len(expected.FUNCTIONS) + len(externals),
            "Endpoint": len(expected.ENDPOINTS),
        }

    def test_files(self, sample_graph):
        g, _ = sample_graph
        rows = sorted(_nodes(g, "File"), key=lambda f: f["path"])
        assert [r["path"] for r in rows] == expected.FILES
        for r in rows:
            assert r["sha256"] == hashlib.sha256((expected.ROOT / r["path"]).read_bytes()).hexdigest()
            assert r["language"] == "python"

    def test_project_functions(self, sample_graph):
        g, _ = sample_graph
        rows = [f for f in _nodes(g, "Function") if f["resolved"] is True]
        assert {f["id"]: (f["kind"], f["start_line"], f["end_line"], f["is_async"]) for f in rows} \
            == expected.FUNCTIONS

    def test_function_properties(self, sample_graph):
        g, _ = sample_graph
        f = g.props("Function", "app/db.py::Repo.get_user")
        assert [f["name"], f["qualified_name"], f["file"]] == ["get_user", "Repo.get_user", "app/db.py"]
        assert f["source"] == (
            "    def get_user(self, name):\n"
            "        cursor = self.conn.cursor()\n"
            "        cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n"
            "        return cursor.fetchone()"
        )

    def test_external_nodes_keep_full_dotted_names(self, sample_graph):
        g, _ = sample_graph
        rows = [f for f in _nodes(g, "Function") if f["resolved"] is False]
        want = {dotted: origin for _, dotted, origin, _ in expected.UNRESOLVED}
        assert {f["qualified_name"]: f["origin"] for f in rows} == want
        for f in rows:
            assert f["id"] == f"external::{f['qualified_name']}"
            assert f["name"] == f["qualified_name"].rsplit(".", 1)[-1]
            assert f["kind"] == "external"

    def test_declares_functions(self, sample_graph):
        g, _ = sample_graph
        rows = [(a, b) for la, a, lb, b, _ in _edges(g, "DECLARES") if lb == "Function"]
        assert set(rows) == {(fid.split("::")[0], fid) for fid in expected.FUNCTIONS}
        # Unresolved callees belong to no file.
        assert not [b for _, b in rows if b.startswith("external::")]

    def test_calls_edges(self, sample_graph):
        g, _ = sample_graph
        rows = _edges(g, "CALLS")
        assert {(a, b): p["lines"] for _, a, _, b, p in rows} == expected.calls_edges()

    def test_resolved_call_targets_are_project_functions(self, sample_graph):
        g, _ = sample_graph
        rows = {(a, b) for _, a, _, b, _ in _edges(g, "CALLS") if g.props("Function", b)["resolved"] is True}
        assert rows == {(a, b) for a, b, _ in expected.RESOLVED}

    def test_endpoints(self, sample_graph):
        g, _ = sample_graph
        declared_by = {b: a for _, a, lb, b, _ in _edges(g, "DECLARES") if lb == "Endpoint"}
        got = {}
        for _, eid, _, handler, _ in _edges(g, "HANDLED_BY"):
            e = g.props("Endpoint", eid)
            got[eid] = (e["method"], e["path"], handler, e["line"], e["auth_required"],
                        tuple(e["auth_evidence"]), e["prefix_resolved"])
            assert declared_by[eid] == handler.split("::")[0]       # declared by the handler's file
            assert e["framework"] == "fastapi"
        assert got == expected.ENDPOINTS

    def test_route_to_sink_paths_exist(self, sample_graph):
        # What Phase 4 builds on: an unauthenticated route reaching a shell sink
        # in 1..4 CALLS hops from its handler.
        g, _ = sample_graph
        paths = []
        for _, eid, _, handler, _ in _edges(g, "HANDLED_BY"):
            if g.props("Endpoint", eid)["auth_required"] is not False:
                continue
            frontier, seen = {handler}, {handler}
            for _ in range(4):
                frontier = {c for f in frontier for c in g.callees_of(f)} - seen
                seen |= frontier
                if "external::subprocess.run" in frontier:
                    paths.append(g.props("Endpoint", eid)["path"])
                    break
        assert paths == ["/api/users/{name}/files"]

    def test_project_node(self, sample_graph):
        g, analysis = sample_graph
        props = _nodes(g, "Project")[0]
        assert props["name"] == "sample_app"
        assert props["root"] == str(expected.ROOT)
        for key, value in analysis.counts().items():
            assert props[key] == value, key

    def test_one_edge_type_per_node_pair(self, sample_graph):
        # Why a DiGraph is enough: each edge type joins its own pair of labels.
        g, _ = sample_graph
        pairs = {}
        for a, b, d in g.g.edges(data=True):
            pairs.setdefault((a[0], b[0]), set()).add(d["type"])
        assert pairs == {("File", "Function"): {"DECLARES"}, ("File", "Endpoint"): {"DECLARES"},
                         ("Endpoint", "Function"): {"HANDLED_BY"}, ("Function", "Function"): {"CALLS"}}
        with pytest.raises(ValueError, match="cannot join"):
            g.merge_edge("CALLS", ("File", "app/db.py"), ("Function", "app/db.py::Repo.get_user"))


class TestRescan:
    def test_rescan_is_idempotent(self):
        name = _name()
        before, after = GraphStore(name), GraphStore(name)
        pipeline.ingest(expected.ROOT, graph=before, graph_name=name)
        pipeline.ingest(expected.ROOT, graph=after, graph_name=name)
        assert _snapshot(before) == _snapshot(after)
        assert len(_snapshot(before)[0]) > 50 and len(_snapshot(before)[1]) > 50

    def test_rescan_removes_what_was_deleted(self, tmp_path):
        project = tmp_path / "sample_app"
        shutil.copytree(expected.ROOT, project)
        pipeline.ingest(project)
        g = GraphStore.load(project)
        assert _count(g, "Function", id="app/routers/debug.py::dump_env") == 1

        # Delete a file, and remove the eval() call from a handler.
        (project / "app/routers/debug.py").unlink()
        admin = project / "app/routers/admin.py"
        admin.write_text(admin.read_text().replace('eval(expr)', 'expr'))
        pipeline.ingest(project)
        g = GraphStore.load(project)

        assert _count(g, "File", path="app/routers/debug.py") == 0
        assert _count(g, "Function", file="app/routers/debug.py") == 0
        assert _count(g, "Endpoint", path="/debug/env") == 0
        # The handler no longer calls eval; other files still do, so the
        # shared eval node stays.
        assert "external::eval" not in g.callees_of("app/routers/admin.py::run_expression")
        assert _count(g, "Function", id="external::eval") == 1
        # dict() and os.popen() were only called from debug.py; os.system still is elsewhere.
        assert _count(g, "Function", id="external::dict") == 0
        assert _count(g, "Function", id="external::os.popen") == 0
        assert _count(g, "Function", id="external::os.system") == 1
        # The handler survives, with its new source (in memory; the cache keeps no source).
        fresh = GraphStore(_name())
        pipeline.ingest(project, graph=fresh, graph_name=fresh.name)
        assert '{"result": expr}' in fresh.props("Function", "app/routers/admin.py::run_expression")["source"]
        assert "source" not in g.props("Function", "app/routers/admin.py::run_expression")
        assert all(p.get("scan_id") for p in _nodes(g, "Function"))

    def test_projects_get_separate_graphs(self, tmp_path):
        sample, flask = tmp_path / "sample_app", tmp_path / "flask_app"
        shutil.copytree(expected.ROOT, sample)
        shutil.copytree(FLASK_ROOT, flask)
        pipeline.ingest(sample)
        pipeline.ingest(flask)
        assert {f["path"] for f in _nodes(GraphStore.load(sample), "File")} == set(expected.FILES)
        assert {f["path"] for f in _nodes(GraphStore.load(flask), "File")} == {"admin.py", "app.py", "views.py"}

    def test_default_graph_name_comes_from_the_path(self, tmp_path):
        project = tmp_path / "flask_app"
        shutil.copytree(FLASK_ROOT, project)
        want = store.graph_name_for(project)
        _, name = pipeline.ingest(project)
        assert name == want
        p = _nodes(GraphStore.load(project), "Project")
        assert [(x["id"], x["root"]) for x in p] == [(want, str(project.resolve()))]
