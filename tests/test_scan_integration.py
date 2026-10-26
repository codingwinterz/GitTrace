"""
test_scan_integration.py — `gittrace scan`, the graph tools and the CLI against a
real FalkorDB.

Scans tests/fixtures/sample_app into its graph (the name graph_name_for gives
the fixture path; dropped afterwards) and checks the exact Sink nodes and
REACHES_SINK edges, the severities stored on them, that the graph-backed scan
agrees with the in-memory one, and every tool's Cypher, unmocked.

Local run:
    docker compose up -d falkordb
    FALKORDB_HOST=localhost FALKORDB_PORT=6379 FALKORDB_PASSWORD= pytest tests/test_scan_integration.py -v

Skips when FalkorDB is unreachable; GITTRACE_REQUIRE_FALKORDB=1 (set in CI)
turns the skip into a failure.
"""

from __future__ import annotations

import json
import os

import pytest
from typer.testing import CliRunner

import expected_findings as expected
import expected_sample_app
from gittrace.cli import app
from gittrace.core import tools
from gittrace.core.scan import scan
from gittrace.graph import connection, store


def _db_reachable() -> bool:
    if not connection.is_local():       # never write test graphs to a remote database
        return False
    try:
        connection.get_db().connection.ping()
        return True
    except Exception:  # noqa: BLE001
        return False


_REACHABLE = _db_reachable()

if not _REACHABLE and os.environ.get("GITTRACE_REQUIRE_FALKORDB") == "1":
    raise RuntimeError(
        f"GITTRACE_REQUIRE_FALKORDB=1 but the {connection.location()} FalkorDB is unreachable "
        "or not local (these tests write graphs; they only run against local Docker)"
    )

pytestmark = pytest.mark.skipif(
    not _REACHABLE,
    reason="no local FalkorDB (start it with `docker compose up -d falkordb`; a remote "
           "FALKORDB_HOST is never used by these tests, which write graphs)",
)

ROOT = expected_sample_app.ROOT
PROJECT = str(ROOT)
runner = CliRunner()


@pytest.fixture(scope="module")
def scanned():
    """One real scan of sample_app, in the graph the tools will look for."""
    db = connection.get_db()
    name = store.graph_name_for(ROOT)
    if name in db.list_graphs():
        db.select_graph(name).delete()
    result = scan(ROOT, blame=False, db=db)
    yield result, db.select_graph(name)
    db.select_graph(name).delete()


def _rows(g, cypher: str, params: dict | None = None) -> list:
    return g.query(cypher, params=params).result_set


class TestSinks:
    def test_one_sink_per_finding(self, scanned):
        _, g = scanned
        rows = _rows(g, "MATCH (s:Sink) RETURN s.id, s.rule_id, s.function")
        assert {r[0]: (r[1], r[2]) for r in rows} == {
            fid: (v[0], v[3]) for fid, v in expected.FINDINGS.items()}

    def test_reaches_sink_edges(self, scanned):
        _, g = scanned
        rows = _rows(g, "MATCH (f:Function)-[:REACHES_SINK]->(s:Sink) RETURN f.id, s.id")
        assert sorted((a, b) for a, b in rows) == sorted(
            (v[3], fid) for fid, v in expected.FINDINGS.items())

    def test_sinks_hang_from_project_functions_only(self, scanned):
        _, g = scanned
        assert _rows(g, ("MATCH (f:Function {resolved: false})-[:REACHES_SINK]->(s) "
                         "RETURN count(s)")) == [[0]]

    def test_severity_is_stored(self, scanned):
        _, g = scanned
        rows = _rows(g, ("MATCH (s:Sink) RETURN s.id, s.severity, s.score, s.uncertain, "
                         "s.endpoints, s.caller_count"))
        assert {r[0]: tuple(r[1:]) for r in rows} == {
            fid: (v[1], v[2], v[7], [e for e, _ in v[5]], len(v[6]))
            for fid, v in expected.FINDINGS.items()}

    def test_site_properties(self, scanned):
        _, g = scanned
        row = _rows(g, ("MATCH (s:Sink {id: 'app/routers/users.py::27::14'}) RETURN s.file, s.line, "
                        "s.column, s.callee, s.param_derived, s.params, s.evidence, s.snippet"))[0]
        assert row == ["app/routers/users.py", 27, 14, "subprocess.check_output", True, ["name"],
                       ["shell=True", "string concatenation (+)", "derived from parameter `name`"],
                       '    output = sp.check_output("ping -c 1 " + name, shell=True)']

    def test_shared_external_nodes_are_not_findings(self, scanned):
        # Three call sites share external::os.system / eval / ... nodes; the
        # findings are the Sinks, one per site.
        _, g = scanned
        assert _rows(g, "MATCH (s:Sink) RETURN count(s)") == [[len(expected.FINDINGS)]]
        assert _rows(g, "MATCH (n:Function {id: 'external::eval'})-[]->(s:Sink) RETURN count(s)") == [[0]]

    def test_project_totals(self, scanned):
        _, g = scanned
        row = _rows(g, ("MATCH (p:Project) RETURN p.findings, p.findings_critical, p.findings_high, "
                        "p.findings_medium"))[0]
        assert row == [13, 7, 1, 5]

    def test_sink_index(self, scanned):
        _, g = scanned
        rows = _rows(g, "CALL db.indexes() YIELD label, properties RETURN label, properties")
        assert ("Sink", ["id"]) in [(label, props) for label, props in rows]


class TestGraphMatchesMemory:
    def test_same_findings_either_way(self, scanned):
        result, _ = scanned
        offline = scan(ROOT, blame=False, offline=True)
        assert [f.to_dict() for f in result.findings] == [f.to_dict() for f in offline.findings]

    def test_json_differs_from_the_snapshot_only_in_the_graph_name(self, scanned):
        result, _ = scanned
        snapshot = json.loads((expected_sample_app.ROOT.parents[1] / "snapshots" /
                               "sample_app_scan.json").read_text(encoding="utf-8"))
        data = result.to_dict()
        assert data.pop("graph") == store.graph_name_for(ROOT)
        snapshot.pop("graph")
        assert data == snapshot


class TestTools:
    def test_list_findings(self, scanned):
        out = tools.list_findings(PROJECT)
        assert "error" not in out, out
        assert [f["id"] for f in out["findings"]] == expected.ORDER
        assert [f["severity"] for f in out["findings"]] == [v[1] for v in expected.FINDINGS.values()]

    def test_list_findings_filters(self, scanned):
        assert tools.list_findings(PROJECT, min_severity="high")["count"] == 8
        out = tools.list_findings(PROJECT, rule_id="GT-SECRET-001")
        assert [f["id"] for f in out["findings"]] == [
            "app/auth.py::4::1", "app/routers/reports.py::8::1", "app/services/maintenance.py::42::9"]

    def test_trace_by_file_and_line(self, scanned):
        out = tools.trace_attack_path(PROJECT, "app/utils/shell.py:8")
        (trace,) = out["traces"]
        assert trace["finding"]["id"] == "app/utils/shell.py::8::9"
        assert [tuple(r["path_nodes"]) for r in trace["routes"]] == [expected.SHELL_LOG_PATH]
        assert trace["routes"][0]["hops"] == 2

    def test_trace_by_id_unauthenticated_first(self, scanned):
        out = tools.trace_attack_path(PROJECT, "app/db.py::17::9")
        routes = out["traces"][0]["routes"]
        assert [(r["endpoint"], r["auth_required"]) for r in routes] == [
            ("GET /api/users/{name} -> app/routers/users.py::read_user", False),
            ("GET /me -> app/main.py::me", True),
        ]

    def test_trace_respects_depth(self, scanned):
        out = tools.trace_attack_path(PROJECT, "app/utils/shell.py:8", depth=1)
        assert out["traces"][0]["routes"] == []

    def test_trace_unknown_line(self, scanned):
        assert tools.trace_attack_path(PROJECT, "app/db.py:99") == {"error": "no finding at app/db.py:99"}

    def test_blast_radius(self, scanned):
        out = tools.blast_radius(PROJECT, "app/db.py::Repo.get_user")
        assert out["callers"] == list(expected.FINDINGS["app/db.py::17::9"][6])
        assert (out["caller_count"], out["endpoint_count"], out["unauthenticated_endpoints"],
                out["total"]) == (3, 2, 1, 5)
        assert out["sinks"] == ["app/db.py::17::9"]

    def test_blast_radius_of_unknown_function(self, scanned):
        assert "no function 'nope'" in tools.blast_radius(PROJECT, "nope")["error"]

    def test_owner_without_blame_asks_git(self, scanned):
        out = tools.finding_owner(PROJECT, "app/routers/admin.py:11")
        (owner,) = out["owners"]
        # The fixture lives in this repository: committed lines have an author.
        assert owner["status"] in ("committed", "uncommitted")
        if owner["status"] == "committed":
            assert owner["owner"]["commit"]

    def test_owner_email_is_stored_but_shown_only_on_request(self, monkeypatch):
        """The graph keeps the full blame author; tool results (MCP) carry the email
        only with GITTRACE_SHOW_EMAIL=1. The fixture's lines are committed in this repository."""
        db = connection.get_db()
        name = "gittrace_test_owner_email"
        try:
            scan(ROOT, blame=True, db=db, graph_name=name)
            rows = db.select_graph(name).query(
                "MATCH (s:Sink) WHERE s.owner_status = 'committed' RETURN properties(s) LIMIT 1").result_set
            if not rows:
                pytest.skip("no committed fixture line (not a git checkout)")
            props = rows[0][0]
            assert props["owner_author"] and props["owner_email"]           # stored in full
            monkeypatch.delenv(tools.SHOW_EMAIL_ENV, raising=False)
            assert "email" not in tools._finding_summary(props)["owner"]
            monkeypatch.setenv(tools.SHOW_EMAIL_ENV, "1")
            assert tools._finding_summary(props)["owner"]["email"] == props["owner_email"]
        finally:
            if name in db.list_graphs():
                db.select_graph(name).delete()

    def test_mcp_owner_hides_the_email_by_default(self, scanned, monkeypatch):
        monkeypatch.delenv(tools.SHOW_EMAIL_ENV, raising=False)
        for owner in tools.finding_owner(PROJECT, "app/routers/admin.py:11")["owners"]:
            assert owner["owner"] is None or "email" not in owner["owner"]
        monkeypatch.setenv(tools.SHOW_EMAIL_ENV, "true")
        for owner in tools.finding_owner(PROJECT, "app/routers/admin.py:11")["owners"]:
            assert owner["owner"] is None or "email" in owner["owner"]


class TestCli:
    def test_graphs_lists_and_drops_exact_names(self):
        db = connection.get_db()
        name = "gittrace_test_graphs_cmd"
        db.select_graph(name).query("CREATE (:Probe {n: 1})")
        try:
            listed = json.loads(runner.invoke(app, ["graphs", "--format", "json"]).stdout)
            assert listed["database"] == "local" and name in listed["graphs"]
            out = runner.invoke(app, ["graphs", "--drop", name + "_missing"])
            assert out.exit_code == 2 and name in db.list_graphs()      # unknown name: nothing deleted
            out = runner.invoke(app, ["graphs", "--drop", name, "--format", "json"])
            assert out.exit_code == 0, out.output
            data = json.loads(out.stdout)
            assert data["dropped"] == [name] and name not in data["graphs"]
            assert name not in db.list_graphs()
        finally:
            if name in db.list_graphs():
                db.select_graph(name).delete()

    def test_trace(self, scanned):
        out = runner.invoke(app, ["trace", "app/utils/shell.py:8", "-p", PROJECT, "--format", "json"])
        assert out.exit_code == 0, out.output
        assert json.loads(out.stdout)["traces"][0]["finding"]["id"] == "app/utils/shell.py::8::9"

    def test_trace_rich(self, scanned):
        out = runner.invoke(app, ["trace", "app/utils/shell.py:8", "-p", PROJECT], env={"COLUMNS": "120"})
        assert out.exit_code == 0, out.output
        for needle in ("GET /api/users/{name}/files", "NO AUTH", "app/utils/shell.py::run_command.log",
                       "os.system  at app/utils/shell.py:8"):
            assert needle in out.output, needle

    def test_trace_unknown_line_exits_2(self, scanned):
        out = runner.invoke(app, ["trace", "app/db.py:99", "-p", PROJECT])
        assert out.exit_code == 2
        assert "no finding at app/db.py:99" in out.output

    def test_blast_radius(self, scanned):
        out = runner.invoke(app, ["blast-radius", "app/db.py::Repo.get_user", "-p", PROJECT])
        assert out.exit_code == 0, out.output
        assert "app/routers/users.py::read_user" in out.output
        assert "BLAST RADIUS" in out.output

    def test_unscanned_project_exits_2(self, tmp_path):
        out = runner.invoke(app, ["blast-radius", "a.py::f", "-p", str(tmp_path)])
        assert out.exit_code == 2
        assert "gittrace scan" in out.output
        assert len([l for l in out.output.splitlines() if l.strip()]) == 1      # errors are not hard-wrapped


class TestRescan:
    def test_rescan_is_idempotent_including_sinks(self, tmp_path):
        db = connection.get_db()
        name = f"gittrace_test_scan_{os.getpid()}"
        try:
            scan(ROOT, blame=False, db=db, graph_name=name)
            g = db.select_graph(name)
            snap = lambda: sorted(  # noqa: E731
                (r[0], json.dumps({k: v for k, v in r[1].items() if k != "scan_id"}, sort_keys=True))
                for r in _rows(g, "MATCH (s:Sink) RETURN s.id, properties(s)"))
            before = snap()
            scan(ROOT, blame=False, db=db, graph_name=name)
            assert snap() == before
            assert _rows(g, "MATCH ()-[e:REACHES_SINK]->() RETURN count(e)") == [[len(expected.FINDINGS)]]
        finally:
            if name in db.list_graphs():
                db.select_graph(name).delete()

    def test_old_schema_is_gone(self, scanned):
        _, g = scanned
        labels = {r[0] for r in _rows(g, "MATCH (n) RETURN DISTINCT labels(n)[0]")}
        assert labels == {"Project", "File", "Function", "Endpoint", "Sink"}
