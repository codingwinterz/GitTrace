"""
test_scan.py — offline tests for `gittrace scan` (no database).

Covers:
  1. sample_app findings, severities, routes and blast radius, exactly
     (expected values in tests/expected_findings.py), with in-memory reachability
  2. the severity model, case by case
  3. bounded depth
  4. owner lookup (git blame parsing, a real throwaway repository, no repository)
  5. the CLI: exit codes, --min-severity, --fail-on, Rich output
  6. the JSON output, against a reviewed snapshot (tests/snapshots/)

Run:  pytest tests/test_scan.py -v
Regenerate the snapshot after an intended change, then review the diff:
    GITTRACE_UPDATE_SNAPSHOTS=1 pytest tests/test_scan.py -k snapshot
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

import expected_findings as expected
import expected_sample_app
from gittrace.cli import app
from gittrace.core.owner import Blamer, _parse_porcelain
from gittrace.core.scan import scan
from gittrace.core.severity import Exposure, score

ROOT = expected_sample_app.ROOT
SNAPSHOT = Path(__file__).resolve().parent / "snapshots" / "sample_app_scan.json"
runner = CliRunner()


@pytest.fixture(scope="module")
def result():
    return scan(ROOT, offline=True, blame=False)


def _summary(f):
    return (f.rule_id, f.severity, f.score, f.function_id, f.params,
            [(r.endpoint_id, r.hops) for r in f.routes], f.callers, f.uncertain)


class TestSampleAppFindings:
    def test_findings_exactly(self, result):
        assert {f.id: _summary(f) for f in result.findings} == expected.FINDINGS

    def test_order(self, result):
        assert [f.id for f in result.findings] == expected.ORDER

    def test_summary(self, result):
        assert result.summary() == expected.SUMMARY

    def test_planted_non_findings_are_not_reported(self, result):
        reported = {(f.file, f.line) for f in result.findings}
        for file, line, why in expected.NOT_FINDINGS:
            assert (file, line) not in reported, why

    def test_deepest_route_node_by_node(self, result):
        f = next(f for f in result.findings if f.id == "app/utils/shell.py::8::9")
        assert f.routes[0].nodes == expected.SHELL_LOG_PATH

    def test_unauthenticated_routes_come_first(self, result):
        f = next(f for f in result.findings if f.id == "app/db.py::17::9")
        assert [r.auth_required for r in f.routes] == [False, True]

    def test_reasons_spell_out_the_score(self, result):
        f = next(f for f in result.findings if f.id == "app/db.py::17::9")
        assert f.reasons == (
            "base severity high (6)",
            "reachable from 1 unauthenticated endpoint(s) (+3)",
            "input derives from a function parameter (+1)",
            "blast radius 5 >= 5 (+1)",
        )

    def test_module_level_secret_gets_a_module_node(self, tmp_path):
        # constants only: no module-level call, so no <module> node until a
        # finding needs one
        (tmp_path / "settings.py").write_text('API_KEY = "sk_live_51HxQ2vLs9Kd8W"\n')
        res = scan(tmp_path, offline=True, blame=False)
        assert [f.function_id for f in res.findings] == ["settings.py::<module>"]
        assert "settings.py::<module>" in {f.id for f in res.analysis.functions}


class TestSeverity:
    @pytest.mark.parametrize("base, flow, param, exposure, level, points", [
        ("high", True, True, Exposure(unauthenticated=1), "critical", 10),
        ("high", True, False, Exposure(unauthenticated=1), "critical", 9),
        ("high", True, True, Exposure(authenticated=2), "high", 8),
        ("high", True, False, Exposure(authenticated=1), "high", 7),
        ("high", True, True, Exposure(), "medium", 5),
        ("high", True, False, Exposure(callers=9), "medium", 5),      # unreachable, blast radius 9
        ("high", True, False, Exposure(unauthenticated=1, callers=4), "critical", 10),
        ("medium", True, False, Exposure(), "low", 2),
        ("medium", False, True, Exposure(unauthenticated=5), "medium", 4),   # secrets ignore reach
        ("low", True, False, Exposure(), "info", 0),
    ])
    def test_table(self, base, flow, param, exposure, level, points):
        sev = score(base, flow, param, exposure)
        assert (sev.level, sev.score) == (level, points)

    def test_uncertain_only_when_deciding_routes_are_unresolved(self):
        assert score("high", True, False, Exposure(unauthenticated=1,
                                                   decided_by_unresolved_prefix=True)).uncertain
        assert not score("high", True, False, Exposure(unauthenticated=1)).uncertain


class TestDepth:
    def test_depth_bounds_reachability(self):
        res = scan(ROOT, offline=True, blame=False, depth=1)
        f = {f.id: f for f in res.findings}
        # list_files -> run_command -> run_command.log needs 2 CALLS hops
        log = f["app/utils/shell.py::8::9"]
        assert (log.reachable, log.callers, log.severity, log.score) == (
            False, ("app/utils/shell.py::run_command",), "medium", 5)
        assert f["app/utils/shell.py::11::12"].reachable

    @pytest.mark.parametrize("depth", [0, 51, -1])
    def test_depth_is_validated(self, depth):
        with pytest.raises(ValueError):
            scan(ROOT, offline=True, blame=False, depth=depth)


PORCELAIN = """\
3f1c2b7a9d8e6f5a4b3c2d1e0f9a8b7c6d5e4f3a 4 4 1
author Ada Lovelace
author-mail <ada@example.com>
author-time 1761400000
author-tz +0000
summary Add the token
filename app/auth.py
\tAPI_TOKEN = "x"
0000000000000000000000000000000000000000 9 9 1
author Not Committed Yet
author-mail <not.committed.yet>
author-time 1761400001
summary Version of app/auth.py from app/auth.py
filename app/auth.py
\tsomething
3f1c2b7a9d8e6f5a4b3c2d1e0f9a8b7c6d5e4f3a 12 12
\tlater line, same commit (headers are not repeated)
"""


class TestOwner:
    def test_porcelain(self):
        owners = _parse_porcelain(PORCELAIN)
        assert owners[4].author == "Ada Lovelace"
        assert owners[4].email == "ada@example.com"
        assert owners[4].commit.startswith("3f1c2b7")
        assert owners[4].date == "2025-10-25T13:46:40+00:00"
        assert owners[4].summary == "Add the token"
        assert owners[9].status == "uncommitted" and owners[9].author is None
        assert owners[12].author == "Ada Lovelace"

    def test_not_a_repository_is_skipped_quietly(self, tmp_path):
        (tmp_path / "app.py").write_text('API_KEY = "sk_live_51HxQ2vLs9Kd8W"\n')
        assert Blamer(tmp_path).enabled is False
        res = scan(tmp_path, offline=True, blame=True)
        assert [f.owner for f in res.findings] == [None]

    @pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
    def test_real_repository(self, tmp_path):
        (tmp_path / "app.py").write_text('import os\n\ndef run(cmd):\n    os.system(cmd)\n')
        git = ["git", "-C", str(tmp_path), "-c", "user.name=Grace Hopper",
               "-c", "user.email=grace@example.com", "-c", "commit.gpgsign=false"]
        subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
        subprocess.run(git + ["add", "app.py"], check=True)
        subprocess.run(git + ["commit", "-q", "-m", "Add run"], check=True)
        with (tmp_path / "app.py").open("a") as fh:
            fh.write("\ndef again(cmd):\n    os.system(cmd)\n")
        res = scan(tmp_path, offline=True, blame=True)
        owners = {f.line: f.owner for f in res.findings}
        assert (owners[4].status, owners[4].author, owners[4].email, owners[4].summary) == (
            "committed", "Grace Hopper", "grace@example.com", "Add run")
        assert owners[7].status == "uncommitted"


class TestCli:
    def _scan(self, *args: str):
        return runner.invoke(app, ["scan", str(ROOT), "--offline", "--no-blame", *args])

    def test_exit_code_gates_on_fail_on(self):
        assert self._scan("--format", "json").exit_code == 1               # default: high
        assert self._scan("--format", "json", "--fail-on", "critical").exit_code == 1
        assert self._scan("--format", "json", "--fail-on", "none").exit_code == 0

    def test_clean_project_exits_zero(self, tmp_path):
        (tmp_path / "ok.py").write_text('def add(a, b):\n    return a + b\n')
        out = runner.invoke(app, ["scan", str(tmp_path), "--offline", "--no-blame"])
        assert out.exit_code == 0, out.output
        assert "NO FINDINGS" in out.output

    def test_threshold_ignores_what_is_below_it(self, tmp_path):
        (tmp_path / "s.py").write_text('API_KEY = "sk_live_51HxQ2vLs9Kd8W"\n')   # one medium
        base = ["scan", str(tmp_path), "--offline", "--no-blame", "--format", "json"]
        assert runner.invoke(app, base).exit_code == 0
        assert runner.invoke(app, base + ["--fail-on", "medium"]).exit_code == 1

    def test_min_severity_filters_the_report_not_the_gate(self):
        out = self._scan("--format", "json", "--min-severity", "critical", "--fail-on", "none")
        data = json.loads(out.stdout)
        assert data["summary"]["total"] == 7
        assert {f["severity"] for f in data["findings"]} == {"critical"}

    def test_bad_path_is_an_error(self, tmp_path):
        out = runner.invoke(app, ["scan", str(tmp_path / "nope"), "--offline"])
        assert out.exit_code == 2

    def test_bad_depth_is_rejected(self):
        assert self._scan("--depth", "0").exit_code == 2

    def test_rich_output(self):
        out = self._scan("--fail-on", "none")
        assert out.exit_code == 0, out.output
        text = out.output
        for needle in ("FINDINGS", "CRITICAL", "7 critical", "GT-SQLI-001", "app/db.py:17",
                       "GET /api/users/{name}", "NO AUTH", "Attack paths",
                       "blast radius: 5", "owner lookup skipped",
                       "> 17         cursor.execute"):
            assert needle in text, needle


class TestJsonSnapshot:
    def test_snapshot(self):
        out = runner.invoke(app, ["scan", str(ROOT), "--offline", "--no-blame",
                                  "--format", "json", "--fail-on", "none"])
        assert out.exit_code == 0, out.output
        if os.environ.get("GITTRACE_UPDATE_SNAPSHOTS") == "1":
            SNAPSHOT.parent.mkdir(exist_ok=True)
            SNAPSHOT.write_text(out.stdout, encoding="utf-8", newline="\n")
        assert json.loads(out.stdout) == json.loads(SNAPSHOT.read_text(encoding="utf-8"))

    def test_snapshot_agrees_with_the_hand_written_expectations(self):
        data = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
        assert data["summary"] == expected.SUMMARY
        got = {
            f["id"]: (f["rule_id"], f["severity"], f["score"], f["function"], tuple(f["params"]),
                      [(r["endpoint"], r["hops"]) for r in f["reachability"]["routes"]],
                      tuple(f["blast_radius"]["callers"]), f["reachability"]["uncertain"])
            for f in data["findings"]
        }
        assert got == expected.FINDINGS
        assert [f["id"] for f in data["findings"]] == expected.ORDER
