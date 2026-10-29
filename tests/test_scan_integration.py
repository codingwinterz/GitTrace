"""
test_scan_integration.py — `gittrace scan`, the graph tools and the CLI against the
real graph store (gittrace.graph.memstore) and its cache.

Scans tests/fixtures/sample_app, which writes its graph cache
(tests/fixtures/sample_app/.gittrace/graph.json, removed afterwards), and
checks the exact Sink nodes and REACHES_SINK edges, the severities stored on
them, that the graph-backed scan agrees with the in-memory one, and every
tool's graph query, unmocked.

    pytest tests/test_scan_integration.py -v
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

import expected_findings as expected
import expected_sample_app
from gittrace.cli import app
from gittrace.core import tools
from gittrace.core.scan import scan
from gittrace.graph import store
from gittrace.graph.memstore import CACHE_FILE, GraphStore

ROOT = expected_sample_app.ROOT
PROJECT = str(ROOT)
runner = CliRunner()


@pytest.fixture(scope="module")
def scanned():
    """One real scan of sample_app, in the cached graph the tools will load."""
    cache = ROOT / CACHE_FILE
    cache.unlink(missing_ok=True)
    result = scan(ROOT, blame=False)
    yield result, GraphStore.load(ROOT)
    cache.unlink(missing_ok=True)


def _sinks(g: GraphStore) -> dict[str, dict]:
    return {s["id"]: s for s in g.sinks()}


def _reaches_sink(g: GraphStore) -> list[tuple[str, str]]:
    return [(a[1], b[1]) for a, b, d in g.g.edges(data=True) if d["type"] == "REACHES_SINK"]


class TestSinks:
    def test_one_sink_per_finding(self, scanned):
        _, g = scanned
        assert {i: (s["rule_id"], s["function"]) for i, s in _sinks(g).items()} == {
            fid: (v[0], v[3]) for fid, v in expected.FINDINGS.items()}

    def test_reaches_sink_edges(self, scanned):
        _, g = scanned
        assert sorted(_reaches_sink(g)) == sorted(
            (v[3], fid) for fid, v in expected.FINDINGS.items())

    def test_sinks_hang_from_project_functions_only(self, scanned):
        _, g = scanned
        assert all(g.props("Function", f)["resolved"] is True for f, _ in _reaches_sink(g))

    def test_severity_is_stored(self, scanned):
        _, g = scanned
        assert {i: (s["severity"], s["score"], s["uncertain"], s["endpoints"], s["caller_count"])
                for i, s in _sinks(g).items()} == {
            fid: (v[1], v[2], v[7], [e for e, _ in v[5]], len(v[6]))
            for fid, v in expected.FINDINGS.items()}

    def test_site_properties(self, scanned):
        _, g = scanned
        s = g.sink("app/routers/users.py::27::14")
        row = [s[k] for k in ("file", "line", "column", "callee", "param_derived", "params", "evidence", "snippet")]
        assert row == ["app/routers/users.py", 27, 14, "subprocess.check_output", True, ["name"],
                       ["shell=True", "string concatenation (+)", "derived from parameter `name`"],
                       '    output = sp.check_output("ping -c 1 " + name, shell=True)']

    def test_shared_external_nodes_are_not_findings(self, scanned):
        # Three call sites share external::os.system / eval / ... nodes; the
        # findings are the Sinks, one per site.
        _, g = scanned
        assert len(g.sinks()) == len(expected.FINDINGS)
        assert not [b for a, b in _reaches_sink(g) if a == "external::eval"]

    def test_project_totals(self, scanned):
        _, g = scanned
        (p,) = g.nodes("Project")
        assert [p["findings"], p["findings_critical"], p["findings_high"], p["findings_medium"]] == [13, 7, 1, 5]

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
        g = GraphStore("gittrace_test_owner_email")
        scan(ROOT, blame=True, graph=g, graph_name=g.name)
        rows = [s for s in g.sinks() if s.get("owner_status") == "committed"]
        if not rows:
            pytest.skip("no committed fixture line (not a git checkout)")
        props = rows[0]
        assert props["owner_author"] and props["owner_email"]           # stored in full
        monkeypatch.delenv(tools.SHOW_EMAIL_ENV, raising=False)
        assert "email" not in tools._finding_summary(props)["owner"]
        monkeypatch.setenv(tools.SHOW_EMAIL_ENV, "1")
        assert tools._finding_summary(props)["owner"]["email"] == props["owner_email"]

    def test_mcp_owner_hides_the_email_by_default(self, scanned, monkeypatch):
        monkeypatch.delenv(tools.SHOW_EMAIL_ENV, raising=False)
        for owner in tools.finding_owner(PROJECT, "app/routers/admin.py:11")["owners"]:
            assert owner["owner"] is None or "email" not in owner["owner"]
        monkeypatch.setenv(tools.SHOW_EMAIL_ENV, "true")
        for owner in tools.finding_owner(PROJECT, "app/routers/admin.py:11")["owners"]:
            assert owner["owner"] is None or "email" in owner["owner"]


class TestCli:
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
    def test_rescan_is_idempotent_including_sinks(self):
        snap = lambda g: sorted(  # noqa: E731
            (s["id"], json.dumps({k: v for k, v in s.items() if k != "scan_id"}, sort_keys=True))
            for s in g.sinks())
        first, second = GraphStore("gittrace_test_scan_a"), GraphStore("gittrace_test_scan_a")
        scan(ROOT, blame=False, graph=first, graph_name=first.name)
        scan(ROOT, blame=False, graph=second, graph_name=second.name)
        assert snap(second) == snap(first)
        assert len(_reaches_sink(second)) == len(expected.FINDINGS)

    def test_old_schema_is_gone(self, scanned):
        _, g = scanned
        labels = {label for label, _ in g.g.nodes}
        assert labels == {"Project", "File", "Function", "Endpoint", "Sink"}
