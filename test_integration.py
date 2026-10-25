"""
test_integration.py — integration tests against a real FalkorDB instance.

Every Cypher query in app.py runs here unmocked. The suite seeds its own
uniquely named graph with seed_graph.seed() and drops it afterwards, so it
never reads or overwrites the demo graph on a shared instance.

Local run (FalkorDB in Docker):
    docker compose up -d falkordb
    FALKORDB_HOST=localhost FALKORDB_PORT=6379 FALKORDB_PASSWORD= pytest test_integration.py -v

The tests skip when FalkorDB is unreachable, so `pytest` stays green on a
machine without a database. CI sets GITTRACE_REQUIRE_FALKORDB=1, which turns
that skip into a failure: there, an unreachable database is a broken build.
"""

from __future__ import annotations

import os
import uuid

import pytest

import app as gittrace_app
import seed_graph
import utils


def _db_reachable() -> bool:
    try:
        utils.get_db().connection.ping()
        return True
    except Exception:  # noqa: BLE001
        return False


_REACHABLE = _db_reachable()

if not _REACHABLE and os.environ.get("GITTRACE_REQUIRE_FALKORDB") == "1":
    raise RuntimeError(
        "GITTRACE_REQUIRE_FALKORDB=1 but FalkorDB is unreachable at "
        f"{utils.FALKORDB_HOST}:{utils.FALKORDB_PORT}"
    )

pytestmark = pytest.mark.skipif(
    not _REACHABLE,
    reason="FalkorDB unreachable (start it with `docker compose up -d falkordb` "
           "or check FALKORDB_HOST / credentials)",
)

TOKEN_PY = "/token-service/token.py"
AUTH_GO = "/auth-service/auth.go"

# Test-only CVE on auth-service.validate_token, which has transitive and
# cross-service callers: handle_request -> route_request -> validate_token.
TEST_CVE = "CVE-2099-0001"


@pytest.fixture(scope="module", autouse=True)
def seeded_graph():
    """Seed a throwaway graph and point every tool at it."""
    name = f"gittrace_test_{uuid.uuid4().hex[:8]}"
    db = utils.get_db()
    seed_graph.seed(db, name)
    g = db.select_graph(name)
    g.query(
        "CREATE (:CVE {id: $id, severity: 'HIGH', description: 'test-only'})",
        params={"id": TEST_CVE},
    )
    seed_graph.link(g, (
        "MATCH (c:CVE {id: $id}) "
        "MATCH (:File {path: $path})-[:DEFINES]->(f:Function {name: 'validate_token'}) "
        "CREATE (c)-[:AFFECTS]->(f)"
    ), {"id": TEST_CVE, "path": AUTH_GO})

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(utils, "GRAPH_NAME", name)
        mp.setattr(gittrace_app, "_ENTITY_CACHE", {})
        yield g
    g.delete()


def _count(g, cypher: str, params: dict | None = None) -> int:
    return g.query(cypher, params=params).result_set[0][0]


class TestSeed:
    def test_every_call_edge_is_created(self, seeded_graph):
        assert _count(seeded_graph, "MATCH ()-[e:CALLS]->() RETURN count(e)") == len(
            seed_graph.CALL_EDGES
        )

    def test_token_service_refresh_edge_exists(self, seeded_graph):
        # Regression: this edge used to be silently dropped because
        # token-service did not define refresh_token.
        assert _count(seeded_graph, (
            "MATCH (:File {path: $p})-[:DEFINES]->(:Function {name: 'refresh_token'})"
            "-[:CALLS]->(:Function {name: 'validate_token'})<-[:DEFINES]-(:File {path: $p}) "
            "RETURN count(*)"
        ), {"p": TOKEN_PY}) == 1

    def test_reseed_is_idempotent(self, seeded_graph):
        before = _count(seeded_graph, "MATCH (n) RETURN count(n)")
        name = utils.GRAPH_NAME
        other = f"{name}_reseed"
        db = utils.get_db()
        try:
            seed_graph.seed(db, other)
            seed_graph.seed(db, other)
            after = _count(db.select_graph(other), "MATCH (n) RETURN count(n)")
        finally:
            db.select_graph(other).delete()
        # The fixture graph has one extra test CVE node on top of the seed.
        assert after == before - 1


class TestBlastRadius:
    def test_seeded_cve_reports_upstream_callers(self):
        out = gittrace_app.get_blast_radius("CVE-2026-4421")
        assert "error" not in out, out.get("error")
        assert out["severity"] == "CRITICAL"
        assert out["affected_function_ids"] == [f"{TOKEN_PY}::validate_token"]
        # Callers of token-service.validate_token, not what it calls.
        assert out["impacted_functions"] == ["refresh_token", "rotate_key"]
        assert out["impacted_function_ids"] == [
            f"{TOKEN_PY}::refresh_token", f"{TOKEN_PY}::rotate_key",
        ]
        assert "parse_claims" not in out["impacted_functions"]
        assert out["impacted_services"] == ["token-service"]
        assert out["service_count"] == 1

    def test_second_seeded_cve(self):
        out = gittrace_app.get_blast_radius("CVE-2026-5513")
        assert out["impacted_functions"] == ["delete_user"]
        assert out["impacted_services"] == ["user-service"]
        assert "update_user" not in out["impacted_functions"]

    def test_transitive_and_cross_service_callers(self):
        out = gittrace_app.get_blast_radius(TEST_CVE)
        assert out["affected_function_ids"] == [f"{AUTH_GO}::validate_token"]
        assert out["impacted_function_ids"] == [
            "/api-gateway/main.py::handle_request",
            "/api-gateway/main.py::route_request",
            f"{AUTH_GO}::issue_token",
            f"{AUTH_GO}::refresh_token",
        ]
        assert out["impacted_services"] == ["api-gateway", "auth-service"]
        assert out["service_count"] == 2

    def test_unknown_cve(self):
        out = gittrace_app.get_blast_radius("CVE-0000-0000")
        assert "error" in out
        assert out["service_count"] == 0


class TestAttackPath:
    def test_cve_scoped(self):
        # When CVE-scoped, the path tool must return the token-service
        # instance (the copy the CVE actually affects), not the auth-service copy.
        path = gittrace_app.find_shortest_dependency_path(
            "api-gateway", "validate_token", cve_id="CVE-2026-4421"
        )
        assert "error" not in path, path
        assert path["path_trace"] == [
            "Service:api-gateway",
            "Service:token-service",
            f"File:{TOKEN_PY}",
            "Function:validate_token",
        ]
        assert path["hop_count"] == 3
        assert path["target_function"] == "validate_token"
        assert path["target_file_path"] == TOKEN_PY
        assert path["cve_id"] == "CVE-2026-4421"

    def test_file_scoped(self):
        path = gittrace_app.find_shortest_dependency_path(
            "api-gateway", "validate_token", target_file_path=AUTH_GO
        )
        assert "error" not in path, path
        assert f"File:{AUTH_GO}" in path["path_trace"]
        assert path["hop_count"] == 3

    def test_unique_name_resolves(self):
        path = gittrace_app.find_shortest_dependency_path("api-gateway", "parse_claims")
        assert "error" not in path, path
        assert path["target_file_path"] == TOKEN_PY
        assert path["path_trace"][-1] == "Function:parse_claims"

    def test_ambiguous_name_is_reported(self):
        path = gittrace_app.find_shortest_dependency_path("api-gateway", "validate_token")
        assert "2 files" in path["error"], path
        assert path["candidates"] == [
            f"{AUTH_GO}::validate_token", f"{TOKEN_PY}::validate_token",
        ]

    def test_unknown_function(self):
        path = gittrace_app.find_shortest_dependency_path("api-gateway", "nope")
        assert "not found" in path["error"]


class TestCodeOwner:
    def test_cve_scoped(self):
        out = gittrace_app.find_code_owner("validate_token", cve_id="CVE-2026-4421")
        assert "error" not in out, out.get("error")
        assert out["file_path"] == TOKEN_PY
        assert out["developer_name"] == "Sarah Chen"
        assert out["email"] == "sarah.chen@acme.com"
        assert out["slack"] == "@sarahc"
        assert out["owned_services"] == ["auth-service", "token-service"]

    def test_file_scoped(self):
        out = gittrace_app.find_code_owner("process_payment",
                                           file_path="/billing-service/billing.py")
        assert out["developer_name"] == "Devon Park"

    def test_unique_name(self):
        out = gittrace_app.find_code_owner("get_user_profile")
        assert out["developer_name"] == "Priya Nair"
        assert out["file_path"] == "/user-service/users.js"

    def test_ambiguous_name_is_reported(self):
        out = gittrace_app.find_code_owner("refresh_token")
        assert "2 files" in out["error"], out
        assert out["candidates"] == [
            f"{AUTH_GO}::refresh_token", f"{TOKEN_PY}::refresh_token",
        ]

    def test_unknown_function(self):
        out = gittrace_app.find_code_owner("ghost")
        assert "error" in out


class TestAgent:
    def test_graph_names_are_exact(self):
        names = gittrace_app._graph_names("Function")
        assert names.count("refresh_token") == 1
        assert "validate_token" in names
        assert gittrace_app._graph_names("Service")[0] == "api-gateway"

    def test_function_for_cve(self):
        assert gittrace_app._function_for_cve("CVE-2026-5513") == "get_user_profile"

    def test_keyword_agent_end_to_end(self):
        resp = gittrace_app.run_agent("Who owns the vulnerable function in CVE-2026-4421?")
        names = [tc.name for tc in resp.tool_calls]
        assert names == ["get_blast_radius", "find_code_owner"]
        assert "Sarah Chen" in resp.answer
        assert TOKEN_PY in resp.answer

    def test_demo_scenario_end_to_end(self):
        demo = gittrace_app.demo_scenario()
        assert demo["blast_radius"]["impacted_functions"] == ["refresh_token", "rotate_key"]
        assert f"File:{TOKEN_PY}" in demo["attack_path"]["path_trace"]
        assert demo["attack_path"]["hop_count"] == 3
        assert demo["attack_path"]["cve_id"] == "CVE-2026-4421"
        assert demo["code_owner"]["developer_name"] == "Sarah Chen"
        assert demo["code_owner"]["file_path"] == TOKEN_PY


@pytest.mark.skipif(
    not (os.environ.get("GEMINI_API_KEY") or os.environ.get("Gemini_API_Key")),
    reason="no Gemini API key configured",
)
class TestLiveAgent:
    """Live agent-loop test with the real LLM. Skips on quota/LLM errors so a
    rate limit doesn't fail the suite; the mock suite in test_app.py already
    covers the loop deterministically."""

    def test_live_llm_answer(self):
        try:
            resp = gittrace_app.run_agent_with_litellm(
                "Which team should I contact urgently about CVE-2026-4421 "
                "and what services are at risk?",
                os.environ.get("LITELLM_MODEL", "gemini/gemini-flash-lite-latest"),
            )
        except Exception as exc:  # noqa: BLE001
            pytest.skip(f"LLM unavailable: {type(exc).__name__}")
        # Whether LLM or fallback answered, the underlying tool data must be right.
        assert resp.cve_id == "CVE-2026-4421"
        assert any(tc.name == "get_blast_radius" for tc in resp.tool_calls)
        assert "token-service" in resp.answer


class TestLiveMCP:
    def test_mcp_tool_call(self):
        import asyncio
        import json

        from mcp_server import server

        result = asyncio.run(server.call_tool(
            "get_blast_radius_tool", {"cve_id": "CVE-2026-4421"}
        ))
        assert result.is_error is False
        payload = json.loads("".join(getattr(c, "text", "") for c in result.content))
        assert payload["impacted_functions"] == ["refresh_token", "rotate_key"]
