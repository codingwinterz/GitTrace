"""
tests/test_connection.py — where the graph goes (gittrace.graph.connection):

  1. local Docker is the default; "local" / "remote" is all GitTrace says
  2. host, port and password are redacted from every message
  3. the status check is a real round trip with a short timeout
  4. graph writes to a remote database need --allow-remote (core, CLI, /scan)

A remote host is simulated by setting the module's settings; nothing here
connects anywhere except check() against a local FalkorDB, when one is up.
"""

from __future__ import annotations

import io
import os
import subprocess
import sys
from pathlib import Path

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError
from rich.console import Console
from typer.testing import CliRunner

import expected_sample_app
from gittrace.cli import app, session
from gittrace.cli.session import CommandError, Session, parse
from gittrace.core import tools
from gittrace.core.scan import scan
from gittrace.graph import connection

ROOT = expected_sample_app.ROOT
REPO = Path(__file__).resolve().parents[1]
HOST, PORT, PASSWORD = "r-secret1234.instance-x.us-central1.gcp.example.cloud", 54824, "hunter2-pw"
runner = CliRunner()


@pytest.fixture
def remote(monkeypatch):
    monkeypatch.setattr(connection, "FALKORDB_HOST", HOST)
    monkeypatch.setattr(connection, "FALKORDB_PORT", PORT)
    monkeypatch.setattr(connection, "FALKORDB_PASSWORD", PASSWORD)
    monkeypatch.setattr(connection, "_db", None)


def _leaks(text: str) -> list[str]:
    return [s for s in (HOST, str(PORT), PASSWORD, "secret1234") if s in text]


class TestDefaults:
    def test_nothing_configured_means_local_docker(self):
        # Empty variables win over .env (load_dotenv does not override), like an unset one.
        env = {**os.environ, "FALKORDB_HOST": "", "FALKORDB_PORT": "", "FALKORDB_PASSWORD": ""}
        out = subprocess.run([sys.executable, "-c", "from gittrace.graph import connection as c; "
                              "print(c.FALKORDB_HOST, c.FALKORDB_PORT, repr(c.FALKORDB_PASSWORD), c.location())"],
                             cwd=REPO, env=env, capture_output=True, text=True, check=True)
        assert out.stdout.split() == ["localhost", "6379", "''", "local"]

    @pytest.mark.parametrize("host, local", [("localhost", True), ("127.0.0.1", True), ("::1", True),
                                             ("LOCALHOST", True), (HOST, False), ("falkordb", False),
                                             ("10.0.0.5", False)])
    def test_local_or_remote(self, host, local):
        assert connection.is_local(host) is local

    def test_location_names_no_host(self, remote):
        assert connection.location() == "remote"


class TestRedaction:
    def test_host_port_and_password_are_removed(self, remote):
        text = connection.redact(f"Error 11001 connecting to {HOST}:{PORT}. AUTH {PASSWORD} failed; port {PORT}")
        assert _leaks(text) == []
        assert "<remote host>" in text and "<password>" in text and "11001" in text

    def test_connect_error_is_redacted(self, remote, monkeypatch):
        def refuse(*args, **kwargs):
            raise RedisConnectionError(f"Error 11001 connecting to {HOST}:{PORT}. getaddrinfo failed.")
        monkeypatch.setattr(connection, "_client", refuse)
        with pytest.raises(RuntimeError) as exc:
            connection.get_db()
        assert _leaks(str(exc.value)) == [] and "remote FalkorDB" in str(exc.value)
        assert exc.value.__cause__ is None and exc.value.__suppress_context__   # no chained host either

    def test_error_during_a_scan_is_redacted(self, remote, monkeypatch):
        class Graph:
            def query(self, *a, **k):
                raise RedisConnectionError(f"Connection to {HOST}:{PORT} closed")

        class Db:
            def select_graph(self, name):
                return Graph()

        with pytest.raises(RuntimeError) as exc:
            scan(ROOT, blame=False, db=Db())
        assert _leaks(str(exc.value)) == [] and "remote FalkorDB failed" in str(exc.value)

    def test_tool_errors_are_redacted(self, remote, monkeypatch):
        class Db:
            def list_graphs(self):
                raise RedisConnectionError(f"Timeout reading from {HOST}:{PORT}")
        monkeypatch.setattr(connection, "get_db", lambda: Db())
        data = tools.blast_radius(str(ROOT), "app/db.py::Repo.get_user", 3)
        assert _leaks(data["error"]) == [] and "remote FalkorDB failed" in data["error"]


class TestCheck:
    def test_success_needs_a_falkordb_command(self, monkeypatch):
        sent, closed = [], []

        class Conn:
            def execute_command(self, *args):
                sent.append(args)

            def close(self):
                closed.append(True)

        class Db:
            connection = Conn()

        kwargs = {}
        monkeypatch.setattr(connection, "_client", lambda *a, **k: kwargs.update(k) or Db())
        assert connection.check() == (True, "GRAPH.LIST answered")
        assert sent == [("GRAPH.LIST",)] and closed == [True]
        assert kwargs == {"socket_connect_timeout": connection.CHECK_TIMEOUT_S,
                          "socket_timeout": connection.CHECK_TIMEOUT_S}

    def test_failure_is_down_and_redacted(self, remote, monkeypatch):
        class Conn:
            def execute_command(self, *args):
                raise RedisConnectionError(f"Timeout connecting to {HOST}:{PORT}")

            def close(self):
                pass

        class Db:
            connection = Conn()

        monkeypatch.setattr(connection, "_client", lambda *a, **k: Db())
        ok, reason = connection.check()
        assert ok is False and _leaks(reason) == []

    def test_status_says_only_up_or_down_and_local_or_remote(self, remote, monkeypatch):
        monkeypatch.setattr(connection, "check", lambda: (True, "GRAPH.LIST answered"))
        assert session.falkordb_status() == ("up", "remote")
        monkeypatch.setattr(connection, "check", lambda: (False, "TimeoutError: <remote host>"))
        assert session.falkordb_status() == ("down", "remote")

    def test_against_the_local_docker(self, monkeypatch):
        """The real thing: a round trip to the local FalkorDB (skips without one)."""
        monkeypatch.setattr(connection, "FALKORDB_HOST", "localhost")
        monkeypatch.setattr(connection, "FALKORDB_PORT", 6379)
        monkeypatch.setattr(connection, "FALKORDB_PASSWORD", "")
        ok, reason = connection.check()
        if not ok:
            if os.environ.get("GITTRACE_REQUIRE_FALKORDB") == "1":
                pytest.fail(f"no local FalkorDB: {reason}")
            pytest.skip(f"no local FalkorDB: {reason}")
        assert reason == "GRAPH.LIST answered"
        monkeypatch.setattr(connection, "FALKORDB_PORT", 1)        # nothing listens there
        assert connection.check(timeout=1.0)[0] is False


class TestRemoteWrites:
    def test_core_refuses_without_allow_remote(self, remote, monkeypatch):
        monkeypatch.setattr(connection, "get_db", lambda: pytest.fail("must not connect"))
        with pytest.raises(connection.RemoteNotAllowed, match="--allow-remote"):
            scan(ROOT, blame=False)
        assert scan(ROOT, blame=False, offline=True).findings            # offline writes nothing: fine

    def test_core_proceeds_with_allow_remote(self, remote, monkeypatch):
        def reached():
            raise RuntimeError("reached the database")
        monkeypatch.setattr(connection, "get_db", reached)
        with pytest.raises(RuntimeError, match="reached the database"):
            scan(ROOT, blame=False, allow_remote=True)

    def test_cli_warns_in_one_line_and_refuses(self, remote, monkeypatch):
        monkeypatch.setattr(connection, "get_db", lambda: pytest.fail("must not connect"))
        out = runner.invoke(app, ["scan", str(ROOT), "--no-llm", "--no-blame"], env={"COLUMNS": "300"})
        assert out.exit_code == 2
        warning = [line for line in out.output.splitlines() if line.startswith("warning:")]
        assert len(warning) == 1 and "remote FalkorDB" in warning[0]
        assert "--allow-remote" in out.output and _leaks(out.output) == []

    def test_cli_with_allow_remote_warns_and_writes(self, remote, monkeypatch):
        seen = {}

        def fake_scan(path, **kwargs):
            seen.update(kwargs)
            return scan(path, blame=False, offline=True)
        monkeypatch.setattr("gittrace.core.scan.scan", fake_scan)
        out = runner.invoke(app, ["scan", str(ROOT), "--no-llm", "--no-blame", "--allow-remote",
                                  "--fail-on", "none"], env={"COLUMNS": "300"})
        assert out.exit_code == 0, out.output
        assert seen["allow_remote"] is True and seen["offline"] is False
        assert sum(line.startswith("warning:") for line in out.output.splitlines()) == 1
        assert _leaks(out.output) == []

    def test_local_needs_no_flag_and_offline_no_warning(self, monkeypatch):
        monkeypatch.setattr(connection, "FALKORDB_HOST", "localhost")
        out = runner.invoke(app, ["scan", str(ROOT), "--offline", "--no-llm", "--no-blame", "--fail-on", "none"])
        assert out.exit_code == 0 and "warning:" not in out.output

    def test_graphs_drop_needs_allow_remote(self, remote, monkeypatch):
        monkeypatch.setattr(connection, "get_db", lambda: pytest.fail("must not connect"))
        out = runner.invoke(app, ["graphs", "--drop", "gittrace_x"])
        assert out.exit_code == 2 and "--allow-remote" in out.output and _leaks(out.output) == []

    def test_interactive_scan_needs_allow_remote(self, remote, monkeypatch):
        console = Console(file=io.StringIO(), width=300, color_system=None)
        monkeypatch.setattr(connection, "get_db", lambda: pytest.fail("must not connect"))
        with pytest.raises(CommandError, match="--allow-remote"):
            Session().run(parse(f'/scan "{ROOT}" --no-llm --no-blame'), console)
        text = console.file.getvalue()
        assert "warning: FALKORDB_HOST is a remote FalkorDB" in text and _leaks(text) == []
