"""
test_integration.py — live integration tests against the real FalkorDB Cloud
instance.

These run the actual graph queries (no mocking) and assert on the seeded demo
data. They skip automatically when FalkorDB is unreachable, so `pytest` stays
green offline while still proving the live path works when the DB is up.

Run:  pytest test_integration.py -v
"""

from __future__ import annotations

import pytest

import app as gittrace_app


def _db_reachable() -> bool:
    try:
        gittrace_app.get_db().connection.ping()
        return True
    except Exception:  # noqa: BLE001
        return False


pytestmark = pytest.mark.skipif(
    not _db_reachable(),
    reason="FalkorDB Cloud unreachable (check FALKORDB_HOST / credentials in .env)",
)


class TestLiveGraph:
    def test_blast_radius_seeded_cve(self):
        out = gittrace_app.get_blast_radius("CVE-2026-4421")
        assert "error" not in out, out.get("error")
        assert out["severity"] == "CRITICAL"
        assert "token-service" in out["impacted_services"]
        assert "parse_claims" in out["impacted_functions"]
        assert out["service_count"] >= 1

    def test_blast_radius_unknown_cve(self):
        out = gittrace_app.get_blast_radius("CVE-0000-0000")
        assert "error" in out
        assert out["service_count"] == 0

    def test_attack_path_seeded(self):
        out = gittrace_app.find_shortest_dependency_path(
            "api-gateway", "validate_token", cve_id="CVE-2026-4421"
        )
        assert "error" not in out, out.get("error")
        assert out["hop_count"] >= 1
        assert any("api-gateway" in n for n in out["path_trace"])
        assert any("validate_token" in n for n in out["path_trace"])
        assert any("token-service" in n for n in out["path_trace"]), out
        assert any("token.py" in n for n in out["path_trace"]), out

    def test_code_owner_seeded(self):
        out = gittrace_app.find_code_owner("validate_token")
        assert "error" not in out, out.get("error")
        assert out["developer_name"] == "Sarah Chen"
        assert out["slack"] == "@sarahc"

    def test_demo_scenario_end_to_end(self):
        # CVE-2026-4421 affects token-service.validate_token; the demo endpoint
        # now calls find_shortest_dependency_path with cve_id so the path is
        # scoped to that instance (not auth-service's copy).
        demo = gittrace_app.demo_scenario()
        assert any("token-service" in n for n in demo['attack_path']['path_trace']), demo
        assert 'File:/token-service/token.py' in demo['attack_path']['path_trace']
        assert demo['attack_path']['hop_count'] == 3
        assert demo['attack_path']['cve_id'] == 'CVE-2026-4421'

    def test_demo_scenario_cve_scoping(self):
        # When CVE-scoped, the path tool must return the token-service instance
        # (the copy the CVE actually affects), not the auth-service copy.
        path = gittrace_app.find_shortest_dependency_path(
            "api-gateway", "validate_token", cve_id="CVE-2026-4421"
        )
        assert "error" not in path, path
        assert path["hop_count"] == 3, path
        assert "Service:token-service" in path["path_trace"], path
        assert "File:/token-service/token.py" in path["path_trace"], path
        assert path["target_function"] == "validate_token"
        assert path["cve_id"] == "CVE-2026-4421"


class TestLiveAgent:
    """Live agent-loop test with the real LLM. Skips on quota/LLM errors so a
    rate limit doesn't fail the suite; the mock suite in test_app.py already
    covers the loop deterministically."""

    def test_live_llm_answer(self):
        try:
            resp = gittrace_app.run_agent_with_litellm(
                "Which team should I contact urgently about CVE-2026-4421 "
                "and what services are at risk?",
                gittrace_app.__dict__.get("LITELLM_MODEL_DEFAULT",
                                          "gemini/gemini-flash-lite-latest"),
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

        from mcp_server import server

        async def _call():
            return await server.call_tool(
                "get_blast_radius_tool", {"cve_id": "CVE-2026-4421"}
            )

        result = asyncio.run(_call())
        # MCP 2.x returns a structured result; normalise to (content, is_error).
        if isinstance(result, tuple):
            content, is_error = result[0], result[1]
        else:
            content = getattr(result, "content", None)
            is_error = getattr(result, "is_error", False)
            if content is None and isinstance(result, dict):
                content = result.get("content", [])
                is_error = result.get("is_error", False)
        assert is_error is False
        joined = "".join(getattr(c, "text", "") for c in content)
        assert "token-service" in joined
