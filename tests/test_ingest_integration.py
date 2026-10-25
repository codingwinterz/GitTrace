"""
test_ingest_integration.py — Python ingestion against a real FalkorDB instance.

Ingests tests/fixtures/sample_app into a uniquely named graph and checks the
exact nodes and edges (expected values in tests/expected_sample_app.py), then
re-scans for idempotency, edits a copy of the project to check that stale
nodes are removed, and ingests a second project to check isolation. Every
graph it creates is dropped afterwards.

Local run (FalkorDB in Docker):
    docker compose up -d falkordb
    FALKORDB_HOST=localhost FALKORDB_PORT=6379 FALKORDB_PASSWORD= pytest tests/test_ingest_integration.py -v

Skips when FalkorDB is unreachable; GITTRACE_REQUIRE_FALKORDB=1 (set in CI)
turns the skip into a failure.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import uuid
from pathlib import Path

import pytest

import expected_sample_app as expected
from gittrace.core import pipeline
from gittrace.graph import connection, store


def _db_reachable() -> bool:
    try:
        connection.get_db().connection.ping()
        return True
    except Exception:  # noqa: BLE001
        return False


_REACHABLE = _db_reachable()

if not _REACHABLE and os.environ.get("GITTRACE_REQUIRE_FALKORDB") == "1":
    raise RuntimeError(
        "GITTRACE_REQUIRE_FALKORDB=1 but FalkorDB is unreachable at "
        f"{connection.FALKORDB_HOST}:{connection.FALKORDB_PORT}"
    )

pytestmark = pytest.mark.skipif(
    not _REACHABLE,
    reason="FalkorDB unreachable (start it with `docker compose up -d falkordb` "
           "or check FALKORDB_HOST / credentials)",
)

FLASK_ROOT = Path(__file__).resolve().parent / "fixtures" / "flask_app"


@pytest.fixture
def graph_names():
    """Unique graph names for a test; every one handed out is dropped after."""
    db = connection.get_db()
    names: list[str] = []

    def make() -> str:
        names.append(f"gittrace_test_ingest_{uuid.uuid4().hex[:8]}")
        return names[-1]

    yield make
    for name in names:
        if name in db.list_graphs():
            db.select_graph(name).delete()


@pytest.fixture(scope="module")
def sample_graph():
    db = connection.get_db()
    name = f"gittrace_test_ingest_{uuid.uuid4().hex[:8]}"
    analysis, _ = pipeline.ingest(expected.ROOT, db=db, graph_name=name)
    g = db.select_graph(name)
    yield g, analysis
    g.delete()


def _rows(g, cypher: str, params: dict | None = None) -> list:
    return g.query(cypher, params=params).result_set


def _snapshot(g) -> tuple[set, set]:
    """Every node and edge with its properties, minus the per-scan stamps."""
    volatile = {"scan_id", "scanned_at"}

    def clean(props: dict) -> tuple:
        return tuple(sorted((k, repr(v)) for k, v in props.items() if k not in volatile))

    nodes = {
        (tuple(labels), clean(props))
        for labels, props in _rows(g, "MATCH (n) RETURN labels(n), properties(n)")
    }
    edges = {
        (a, t, b, clean(props))
        for a, t, b, props in _rows(g, (
            "MATCH (x)-[r]->(y) "
            "RETURN coalesce(x.id, x.path), type(r), coalesce(y.id, y.path), properties(r)"
        ))
    }
    return nodes, edges


class TestSampleAppGraph:
    def test_node_counts_by_label(self, sample_graph):
        g, _ = sample_graph
        counts = dict(_rows(g, "MATCH (n) RETURN labels(n)[0], count(n)"))
        externals = {dotted for _, dotted, _, _ in expected.UNRESOLVED}
        assert counts == {
            "Project": 1,
            "File": len(expected.FILES),
            "Function": len(expected.FUNCTIONS) + len(externals),
            "Endpoint": len(expected.ENDPOINTS),
        }

    def test_files(self, sample_graph):
        g, _ = sample_graph
        rows = _rows(g, "MATCH (f:File) RETURN f.path, f.sha256, f.language ORDER BY f.path")
        assert [r[0] for r in rows] == expected.FILES
        for path, sha, language in rows:
            assert sha == hashlib.sha256((expected.ROOT / path).read_bytes()).hexdigest()
            assert language == "python"

    def test_project_functions(self, sample_graph):
        g, _ = sample_graph
        rows = _rows(g, (
            "MATCH (f:Function {resolved: true}) "
            "RETURN f.id, f.kind, f.start_line, f.end_line, f.is_async"
        ))
        assert {r[0]: tuple(r[1:]) for r in rows} == expected.FUNCTIONS

    def test_function_properties(self, sample_graph):
        g, _ = sample_graph
        row = _rows(g, (
            "MATCH (f:Function {id: $id}) "
            "RETURN f.name, f.qualified_name, f.file, f.source"
        ), {"id": "app/db.py::Repo.get_user"})[0]
        assert row[:3] == ["get_user", "Repo.get_user", "app/db.py"]
        assert row[3] == (
            "    def get_user(self, name):\n"
            "        cursor = self.conn.cursor()\n"
            "        cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n"
            "        return cursor.fetchone()"
        )

    def test_external_nodes_keep_full_dotted_names(self, sample_graph):
        g, _ = sample_graph
        rows = _rows(g, (
            "MATCH (f:Function {resolved: false}) "
            "RETURN f.id, f.qualified_name, f.name, f.kind, f.origin"
        ))
        want = {dotted: origin for _, dotted, origin, _ in expected.UNRESOLVED}
        assert {r[1]: r[4] for r in rows} == want
        for fid, dotted, name, kind, _ in rows:
            assert fid == f"external::{dotted}"
            assert name == dotted.rsplit(".", 1)[-1]
            assert kind == "external"

    def test_declares_functions(self, sample_graph):
        g, _ = sample_graph
        rows = _rows(g, "MATCH (f:File)-[:DECLARES]->(fn:Function) RETURN f.path, fn.id")
        assert {(p, fid) for p, fid in rows} == {(fid.split("::")[0], fid) for fid in expected.FUNCTIONS}
        # Unresolved callees belong to no file.
        assert _rows(g, "MATCH (:File)-[:DECLARES]->(f:Function {resolved: false}) RETURN count(f)") == [[0]]

    def test_calls_edges(self, sample_graph):
        g, _ = sample_graph
        rows = _rows(g, "MATCH (a:Function)-[c:CALLS]->(b:Function) RETURN a.id, b.id, c.lines")
        assert {(a, b): lines for a, b, lines in rows} == expected.calls_edges()

    def test_resolved_call_targets_are_project_functions(self, sample_graph):
        g, _ = sample_graph
        rows = _rows(g, (
            "MATCH (a:Function)-[:CALLS]->(b:Function {resolved: true}) RETURN a.id, b.id"
        ))
        assert {(a, b) for a, b in rows} == {(a, b) for a, b, _ in expected.RESOLVED}

    def test_endpoints(self, sample_graph):
        g, _ = sample_graph
        rows = _rows(g, (
            "MATCH (f:File)-[:DECLARES]->(e:Endpoint)-[:HANDLED_BY]->(h:Function) "
            "RETURN e.id, e.method, e.path, h.id, e.line, e.auth_required, e.auth_evidence, "
            "e.prefix_resolved, f.path, e.framework"
        ))
        got = {r[0]: (r[1], r[2], r[3], r[4], r[5], tuple(r[6]), r[7]) for r in rows}
        assert got == expected.ENDPOINTS
        for r in rows:
            assert r[8] == r[3].split("::")[0]       # declared by the handler's file
            assert r[9] == "fastapi"

    def test_route_to_sink_paths_exist(self, sample_graph):
        # What Phase 4 builds on: an unauthenticated route reaching a shell sink.
        g, _ = sample_graph
        rows = _rows(g, (
            "MATCH (e:Endpoint {auth_required: false})-[:HANDLED_BY]->(:Function)"
            "-[:CALLS*1..4]->(s:Function {id: 'external::subprocess.run'}) RETURN e.path"
        ))
        assert [r[0] for r in rows] == ["/api/users/{name}/files"]

    def test_project_node(self, sample_graph):
        g, analysis = sample_graph
        props = _rows(g, "MATCH (p:Project) RETURN properties(p)")[0][0]
        assert props["name"] == "sample_app"
        assert props["root"] == str(expected.ROOT)
        for key, value in analysis.counts().items():
            assert props[key] == value, key

    def test_indexes(self, sample_graph):
        g, _ = sample_graph
        rows = _rows(g, "CALL db.indexes() YIELD label, properties RETURN label, properties")
        indexed = {(label, p) for label, props in rows for p in props}
        assert {("Function", "id"), ("File", "path"), ("Endpoint", "id")} <= indexed


class TestRescan:
    def test_rescan_is_idempotent(self, graph_names):
        db = connection.get_db()
        name = graph_names()
        pipeline.ingest(expected.ROOT, db=db, graph_name=name)
        before = _snapshot(db.select_graph(name))
        pipeline.ingest(expected.ROOT, db=db, graph_name=name)
        after = _snapshot(db.select_graph(name))
        assert before == after
        assert len(before[0]) > 50 and len(before[1]) > 50

    def test_rescan_removes_what_was_deleted(self, graph_names, tmp_path):
        db = connection.get_db()
        name = graph_names()
        project = tmp_path / "sample_app"
        shutil.copytree(expected.ROOT, project)
        pipeline.ingest(project, db=db, graph_name=name)
        g = db.select_graph(name)
        assert _rows(g, "MATCH (f:Function {id: 'app/routers/debug.py::dump_env'}) RETURN count(f)") == [[1]]

        # Delete a file, and remove the eval() call from a handler.
        (project / "app/routers/debug.py").unlink()
        admin = project / "app/routers/admin.py"
        admin.write_text(admin.read_text().replace('eval(expr)', 'expr'))
        pipeline.ingest(project, db=db, graph_name=name)

        assert _rows(g, "MATCH (f:File {path: 'app/routers/debug.py'}) RETURN count(f)") == [[0]]
        assert _rows(g, "MATCH (f:Function) WHERE f.file = 'app/routers/debug.py' RETURN count(f)") == [[0]]
        assert _rows(g, "MATCH (e:Endpoint {path: '/debug/env'}) RETURN count(e)") == [[0]]
        # The handler no longer calls eval; other files still do, so the
        # shared eval node stays.
        assert _rows(g, (
            "MATCH (:Function {id: 'app/routers/admin.py::run_expression'})"
            "-[c:CALLS]->(:Function {id: 'external::eval'}) RETURN count(c)")) == [[0]]
        assert _rows(g, "MATCH (f:Function {id: 'external::eval'}) RETURN count(f)") == [[1]]
        # dict() and os.popen() were only called from debug.py; os.system still is elsewhere.
        assert _rows(g, "MATCH (f:Function {id: 'external::dict'}) RETURN count(f)") == [[0]]
        assert _rows(g, "MATCH (f:Function {id: 'external::os.popen'}) RETURN count(f)") == [[0]]
        assert _rows(g, "MATCH (f:Function {id: 'external::os.system'}) RETURN count(f)") == [[1]]
        # The handler survives, with its new source.
        src = _rows(g, "MATCH (f:Function {id: 'app/routers/admin.py::run_expression'}) RETURN f.source")
        assert '{"result": expr}' in src[0][0]
        assert _rows(g, "MATCH (f:Function) WHERE f.scan_id IS NULL RETURN count(f)") == [[0]]

    def test_projects_get_separate_graphs(self, graph_names):
        db = connection.get_db()
        sample_name, flask_name = graph_names(), graph_names()
        pipeline.ingest(expected.ROOT, db=db, graph_name=sample_name)
        pipeline.ingest(FLASK_ROOT, db=db, graph_name=flask_name)
        sample_files = {r[0] for r in _rows(db.select_graph(sample_name), "MATCH (f:File) RETURN f.path")}
        flask_files = {r[0] for r in _rows(db.select_graph(flask_name), "MATCH (f:File) RETURN f.path")}
        assert sample_files == set(expected.FILES)
        assert flask_files == {"admin.py", "app.py", "views.py"}

    def test_default_graph_name_comes_from_the_path(self):
        db = connection.get_db()
        want = store.graph_name_for(FLASK_ROOT)
        try:
            _, name = pipeline.ingest(FLASK_ROOT, db=db)
            assert name == want
            assert want in db.list_graphs()
            project = _rows(db.select_graph(want), "MATCH (p:Project) RETURN p.id, p.root")
            assert project == [[want, str(FLASK_ROOT)]]
        finally:
            if want in db.list_graphs():
                db.select_graph(want).delete()
