"""
test_app.py — automated test suite for GitTrace.

Covers:
  1. Pure helper functions (CVE / function / service extraction, answer synthesis)
  2. Graph tools with a mocked FalkorDB layer (no live DB required)
  3. FastAPI endpoints via TestClient
  4. The LiteLLM agent loop with a fully mocked LLM, so tests never hit the
     Gemini API or depend on its quota.

Run:  pytest test_app.py -v
"""

from __future__ import annotations

import inspect
import json
import os
import subprocess
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import app as gittrace_app
import mcp_server
import seed_graph
from app import (
    TOOL_REGISTRY,
    AgentResponse,
    GraphTool,
    QueryRequest,
    ToolCall,
    _extract_cve_id,
    _extract_function_name,
    _extract_public_service,
    _synthesize_answer,
    app,
    find_code_owner,
    find_shortest_dependency_path,
    get_blast_radius,
    run_agent,
    run_agent_with_litellm,
    tool_schemas,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def mock_graph() -> MagicMock:
    """A mock FalkorDB graph whose .query() returns a canned result_set."""
    g = MagicMock()
    return g


def _fake_query_result(result_set):
    """Wrap a result_set in the shape returned by FalkorDB's graph.query()."""
    return SimpleNamespace(result_set=result_set)


# get_blast_radius row: cve, severity, services, caller names, service count,
# affected function ids, caller ids. The callers are the functions that CALL
# token-service.validate_token, not what it calls (parse_claims).
BLAST_ROW = [
    "CVE-2026-4421", "CRITICAL", ["token-service"],
    ["rotate_key", "refresh_token"], 1,
    ["/token-service/token.py::validate_token"],
    ["/token-service/token.py::rotate_key", "/token-service/token.py::refresh_token"],
]

# find_code_owner row: file path, function, developer, email, slack, owned services.
OWNER_ROW = [
    "/token-service/token.py", "validate_token",
    "Sarah Chen", "sarah.chen@acme.com", "@sarahc", ["auth-service", "token-service"],
]

TOKEN_PY = "/token-service/token.py"
AUTH_GO = "/auth-service/auth.go"


# ---------------------------------------------------------------------------
# 1. Helper functions
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_extract_cve_id_present(self):
        assert _extract_cve_id("alert: CVE-2026-4421 in auth") == "CVE-2026-4421"

    def test_extract_cve_id_uppercased(self):
        assert _extract_cve_id("cve-2026-4421") == "CVE-2026-4421"

    def test_extract_cve_id_absent(self):
        assert _extract_cve_id("no vulnerability here") is None

    def test_extract_function_name_known(self):
        assert _extract_function_name("who owns validate_token?") == "validate_token"

    def test_extract_function_name_unknown(self):
        assert _extract_function_name("tell me a joke") is None

    def test_extract_public_service_known(self):
        assert _extract_public_service("from api-gateway to X") == "api-gateway"

    def test_extract_public_service_unknown(self):
        assert _extract_public_service("from nowhere to X") is None

    def test_extract_function_name_uses_graph_names(self):
        # Functions outside the old hardcoded list must still be recognized.
        with patch.object(gittrace_app, "_graph_names",
                          return_value=["delete_user", "refresh_token"]):
            assert _extract_function_name("who owns delete_user?") == "delete_user"
            assert _extract_function_name("who owns refresh_token?") == "refresh_token"

    def test_extract_public_service_uses_graph_names(self):
        with patch.object(gittrace_app, "_graph_names",
                          return_value=["billing-service", "user-service"]):
            assert _extract_public_service(
                "path from billing-service to process_payment"
            ) == "billing-service"

    def test_extract_matches_whole_words_only(self):
        # The old lookup was a lowercased substring search: 'token' matched
        # inside 'refresh_token', and 'validate_token' inside 'validate_token_v2'.
        with patch.object(gittrace_app, "_graph_names",
                          return_value=["token", "validate_token", "refresh_token"]):
            assert _extract_function_name("who owns refresh_token?") == "refresh_token"
            assert _extract_function_name("who owns validate_token_v2?") is None
            assert _extract_function_name("path to validate_token.") == "validate_token"

    def test_extract_preserves_case(self):
        # Names are returned exactly as stored, so they still match when
        # handed to a tool; a lowercased mention is not the same identifier.
        with patch.object(gittrace_app, "_graph_names",
                          return_value=["Repo.get_user"]):
            assert _extract_function_name("who owns Repo.get_user?") == "Repo.get_user"
            assert _extract_function_name("who owns repo.get_user?") is None

    def test_graph_names_are_not_lowercased(self, mock_graph, monkeypatch):
        monkeypatch.setattr(gittrace_app, "_ENTITY_CACHE", {})
        mock_graph.query.return_value = _fake_query_result(
            [["Repo.get_user"], ["validate_token"]]
        )
        with patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            names = gittrace_app._graph_names("Function")
        assert names == ["Repo.get_user", "validate_token"]

    def test_extract_falls_back_when_graph_unavailable(self):
        with patch.object(gittrace_app, "_graph_names", return_value=[]):
            assert _extract_function_name("who owns validate_token?") == "validate_token"
            assert _extract_public_service("from api-gateway to X") == "api-gateway"

    def test_synthesize_no_tool_calls(self):
        out = _synthesize_answer("q", [], [], None)
        assert "couldn't identify" in out

    def test_synthesize_blast_radius(self):
        calls = [ToolCall(name="get_blast_radius", arguments={"cve_id": "CVE-2026-4421"})]
        results = [{"name": "get_blast_radius", "result": {
            "cve_id": "CVE-2026-4421", "severity": "CRITICAL",
            "affected_function_ids": [f"{TOKEN_PY}::validate_token"],
            "impacted_services": ["token-service"],
            "impacted_functions": ["refresh_token", "rotate_key"],
            "service_count": 1,
        }}]
        out = _synthesize_answer("q", calls, results, "CVE-2026-4421")
        assert "CVE-2026-4421" in out
        assert "CRITICAL" in out
        assert "token-service" in out
        assert f"{TOKEN_PY}::validate_token" in out
        assert "Upstream callers: refresh_token, rotate_key" in out

    def test_synthesize_reports_tool_errors(self):
        calls = [ToolCall(name="find_code_owner", arguments={"function_name": "validate_token"})]
        results = [{"name": "find_code_owner", "result": {"error": "ambiguous"}}]
        assert _synthesize_answer("q", calls, results, None) == "[code owner] ambiguous"

    def test_synthesize_attack_path(self):
        calls = [ToolCall(name="find_shortest_dependency_path",
                          arguments={"start_service": "api-gateway", "target_function": "validate_token"})]
        results = [{"name": "find_shortest_dependency_path", "result": {
            "start_service": "api-gateway", "target_function": "validate_token",
            "path_trace": ["Service:api-gateway", "Function:validate_token"],
            "hop_count": 1,
        }}]
        out = _synthesize_answer("q", calls, results, None)
        assert "api-gateway" in out and "validate_token" in out

    def test_synthesize_code_owner(self):
        calls = [ToolCall(name="find_code_owner", arguments={"function_name": "validate_token"})]
        results = [{"name": "find_code_owner", "result": {
            "function_name": "validate_token", "developer_name": "Sarah Chen",
            "email": "sarah.chen@acme.com", "slack": "@sarahc",
            "owned_services": ["auth-service"],
        }}]
        out = _synthesize_answer("q", calls, results, None)
        assert "Sarah Chen" in out and "@sarahc" in out


# ---------------------------------------------------------------------------
# 2. Graph tools (mocked FalkorDB)
# ---------------------------------------------------------------------------

class TestGraphTools:
    def test_tool_schemas_shape(self):
        schemas = tool_schemas()
        assert [s["function"]["name"] for s in schemas] == list(TOOL_REGISTRY)
        assert {"get_blast_radius", "find_shortest_dependency_path",
                "find_code_owner"} <= set(TOOL_REGISTRY)
        for s in schemas:
            assert s["type"] == "function"
            assert "parameters" in s["function"]

    def test_get_blast_radius_walks_callers_not_callees(self, mock_graph):
        # Regression: the blast radius used to follow CALLS *out* of the
        # vulnerable function, reporting what it calls (parse_claims) instead
        # of the code that breaks when it does.
        mock_graph.query.return_value = _fake_query_result([BLAST_ROW])
        with patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            get_blast_radius("CVE-2026-4421")
        cypher_sent = mock_graph.query.call_args[0][0]
        assert "(caller:Function)-[:CALLS*1..5]->(f)" in cypher_sent, cypher_sent
        assert "(f)-[:CALLS" not in cypher_sent, cypher_sent

    def test_get_blast_radius(self, mock_graph):
        mock_graph.query.return_value = _fake_query_result(
            [BLAST_ROW]
        )
        with patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            out = get_blast_radius("CVE-2026-4421")
        assert out["cve_id"] == "CVE-2026-4421"
        assert out["severity"] == "CRITICAL"
        assert out["affected_function_ids"] == [f"{TOKEN_PY}::validate_token"]
        assert out["impacted_services"] == ["token-service"]
        # Sorted, regardless of the order collect() produced.
        assert out["impacted_functions"] == ["refresh_token", "rotate_key"]
        assert out["impacted_function_ids"] == [
            f"{TOKEN_PY}::refresh_token", f"{TOKEN_PY}::rotate_key",
        ]
        assert out["service_count"] == 1

    def test_get_blast_radius_not_found(self, mock_graph):
        mock_graph.query.return_value = _fake_query_result([])
        with patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            out = get_blast_radius("CVE-0000-0000")
        assert "error" in out
        assert out["service_count"] == 0

    def test_find_shortest_dependency_path(self, mock_graph):
        # A name defined in exactly one file resolves to that file, then the
        # path query is scoped by (file path, name).
        mock_graph.query.side_effect = [
            _fake_query_result([[TOKEN_PY]]),
            _fake_query_result([[["Service:api-gateway", "Function:parse_claims"], 1,
                                 TOKEN_PY]]),
        ]
        with patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            out = find_shortest_dependency_path("api-gateway", "parse_claims")
        assert out["hop_count"] == 1
        assert "Service:api-gateway" in out["path_trace"]
        assert out["target_function"] == "parse_claims"
        assert out["target_file_path"] == TOKEN_PY
        assert out["cve_id"] is None
        params_sent = mock_graph.query.call_args[1]["params"]
        assert params_sent["target_file_path"] == TOKEN_PY

    def test_find_shortest_dependency_path_ambiguous_name(self, mock_graph):
        # Regression: a bare name defined in two files used to resolve to
        # whichever copy was closest. Now it is reported, with candidates.
        mock_graph.query.return_value = _fake_query_result([[AUTH_GO], [TOKEN_PY]])
        with patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            out = find_shortest_dependency_path("api-gateway", "validate_token")
        assert "2 files" in out["error"], out
        assert out["candidates"] == [
            f"{AUTH_GO}::validate_token", f"{TOKEN_PY}::validate_token",
        ]
        assert out["path_trace"] == []
        assert mock_graph.query.call_count == 1  # no path query was attempted

    def test_find_shortest_dependency_path_cve_scoped(self, mock_graph):
        mock_graph.query.return_value = _fake_query_result(
            [[["Service:api-gateway", "Service:token-service",
               "File:/token-service/token.py", "Function:validate_token"], 3, TOKEN_PY]]
        )
        with patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            out = find_shortest_dependency_path(
                "api-gateway", "validate_token", cve_id="CVE-2026-4421"
            )
        assert out["hop_count"] == 3
        assert "Service:token-service" in out["path_trace"]
        assert "File:/token-service/token.py" in out["path_trace"]
        assert out["target_function"] == "validate_token"
        assert out["cve_id"] == "CVE-2026-4421", out
        # Regression guard: with a CVE context the Cypher must derive the target
        # from the AFFECTS edge (same source as get_blast_radius) instead of
        # matching Function by name alone — otherwise the tool silently falls
        # back to the auth-service copy.
        cypher_sent = mock_graph.query.call_args[0][0]
        params_sent = mock_graph.query.call_args[1].get("params", {})
        assert ")-[:AFFECTS]->(f:Function)" in cypher_sent, cypher_sent
        assert params_sent.get("cve_id") == "CVE-2026-4421", params_sent

    def test_find_shortest_dependency_path_cve_respects_resolved_target(self, mock_graph):
        # CVE that affects a *different* function than the hardcoded classifier
        # guess. Regression: the returned target_function must come from the
        # resolved path_trace, not from the input parameter, otherwise a
        # CVE-scoped path_trace ending at get_user_profile could still claim
        # target_function == "validate_token", which is internally inconsistent.
        mock_graph.query.return_value = _fake_query_result(
            [[["Service:api-gateway", "Service:profile-service",
               "File:/profile-service/profile.py", "Function:get_user_profile"], 3,
              "/profile-service/profile.py"]]
        )
        with patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            out = find_shortest_dependency_path(
                "api-gateway", "validate_token", cve_id="CVE-2026-5513"
            )
        assert out["hop_count"] == 3
        assert "File:/profile-service/profile.py" in out["path_trace"]
        assert out["target_function"] == "get_user_profile", (
            f"target_function should be derived from the resolved path,"
            f" not the input param; got {out['target_function']!r}"
        )
        assert out["cve_id"] == "CVE-2026-5513", out

    def test_find_shortest_dependency_path_file_scoped(self, mock_graph):
        mock_graph.query.return_value = _fake_query_result(
            [[["Service:api-gateway", "Service:auth-service",
               "File:/auth-service/auth.go", "Function:validate_token"], 3, AUTH_GO]]
        )
        with patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            out = find_shortest_dependency_path(
                "api-gateway", "validate_token", target_file_path="/auth-service/auth.go"
            )
        assert out["hop_count"] == 3
        assert "File:/auth-service/auth.go" in out["path_trace"]
        assert out["target_function"] == "validate_token"
        assert out["cve_id"] is None, out["cve_id"]

    def test_find_shortest_dependency_path_none(self, mock_graph):
        mock_graph.query.return_value = _fake_query_result([])
        with patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            out = find_shortest_dependency_path("nope", "nope")
        assert "error" in out

    def test_find_code_owner(self, mock_graph):
        mock_graph.query.return_value = _fake_query_result(
            [OWNER_ROW]
        )
        with patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            out = find_code_owner("validate_token")
        assert out["developer_name"] == "Sarah Chen"
        assert out["slack"] == "@sarahc"
        assert out["file_path"] == TOKEN_PY
        assert out["owned_services"] == ["auth-service", "token-service"]
        assert [o["developer_name"] for o in out["owners"]] == ["Sarah Chen"]
        cypher_sent = mock_graph.query.call_args[0][0]
        assert "LIMIT" not in cypher_sent, cypher_sent
        assert "ORDER BY" in cypher_sent, cypher_sent

    def test_find_code_owner_ambiguous_name(self, mock_graph):
        # Regression: LIMIT 1 with no ORDER BY used to answer with whichever
        # validate_token row the graph returned first.
        mock_graph.query.return_value = _fake_query_result([
            [AUTH_GO, "validate_token", "Sarah Chen", "sarah.chen@acme.com", "@sarahc", []],
            [TOKEN_PY, "validate_token", "Sarah Chen", "sarah.chen@acme.com", "@sarahc", []],
        ])
        with patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            out = find_code_owner("validate_token")
        assert "2 files" in out["error"], out
        assert out["developer_name"] is None
        assert out["candidates"] == [
            f"{AUTH_GO}::validate_token", f"{TOKEN_PY}::validate_token",
        ]

    def test_find_code_owner_cve_scoped(self, mock_graph):
        mock_graph.query.return_value = _fake_query_result([OWNER_ROW])
        with patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            out = find_code_owner("anything", cve_id="CVE-2026-4421")
        cypher_sent = mock_graph.query.call_args[0][0]
        params_sent = mock_graph.query.call_args[1]["params"]
        assert ")-[:AFFECTS]->(f:Function)" in cypher_sent, cypher_sent
        assert params_sent["cve_id"] == "CVE-2026-4421"
        # The resolved function is reported, not the name passed in.
        assert out["function_name"] == "validate_token"
        assert out["file_path"] == TOKEN_PY

    def test_find_code_owner_file_scoped(self, mock_graph):
        mock_graph.query.return_value = _fake_query_result([
            [AUTH_GO, "validate_token", "Sarah Chen", "sarah.chen@acme.com", "@sarahc",
             ["auth-service", "token-service"]],
        ])
        with patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            out = find_code_owner("validate_token", file_path=AUTH_GO)
        cypher_sent = mock_graph.query.call_args[0][0]
        params_sent = mock_graph.query.call_args[1]["params"]
        assert "(file:File {path: $file_path})" in cypher_sent, cypher_sent
        assert params_sent["file_path"] == AUTH_GO
        assert out["file_path"] == AUTH_GO

    def test_find_code_owner_file_without_author(self, mock_graph):
        mock_graph.query.return_value = _fake_query_result(
            [[TOKEN_PY, "parse_claims", None, None, None, []]]
        )
        with patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            out = find_code_owner("parse_claims")
        assert "No owner found" in out["error"]
        assert out["file_path"] == TOKEN_PY

    def test_find_code_owner_none(self, mock_graph):
        mock_graph.query.return_value = _fake_query_result([])
        with patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            out = find_code_owner("ghost")
        assert "error" in out


# ---------------------------------------------------------------------------
# 3. Keyword classifier (run_agent)
# ---------------------------------------------------------------------------

class TestRunAgent:
    def test_cve_question_calls_blast_radius(self, mock_graph):
        mock_graph.query.return_value = _fake_query_result(
            [BLAST_ROW]
        )
        with patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            resp = run_agent("What's the blast radius of CVE-2026-4421?")
        assert isinstance(resp, AgentResponse)
        assert resp.cve_id == "CVE-2026-4421"
        assert any(tc.name == "get_blast_radius" for tc in resp.tool_calls)
        assert "token-service" in resp.answer

    def test_owner_question_calls_code_owner(self, mock_graph):
        mock_graph.query.return_value = _fake_query_result(
            [OWNER_ROW]
        )
        with patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            resp = run_agent("Who owns validate_token?")
        assert any(tc.name == "find_code_owner" for tc in resp.tool_calls)
        assert "Sarah Chen" in resp.answer

    def test_auth_failure_short_circuits_later_calls(self, mock_graph):
        # A rejected API key must not cost a failed round-trip on every message.
        mock_graph.query.return_value = _fake_query_result(
            [BLAST_ROW]
        )

        class AuthenticationError(Exception):
            pass

        failing = MagicMock()
        failing.completion.side_effect = AuthenticationError("API key not valid")
        try:
            with patch.dict(sys.modules, {"litellm": failing}), \
                 patch.object(gittrace_app, "get_graph", return_value=mock_graph):
                first = run_agent_with_litellm(
                    "blast radius of CVE-2026-4421", "gemini/gemini-3.8-flash"
                )
            assert "token-service" in first.answer
            assert gittrace_app._llm_auth_cooldown_active()

            healthy = _make_litellm_mock(
                _tool_call_response("get_blast_radius", {"cve_id": "CVE-2026-4421"}),
                _text_response("should not be used while the cooldown is active"),
            )
            with patch.dict(sys.modules, {"litellm": healthy}), \
                 patch.object(gittrace_app, "get_graph", return_value=mock_graph):
                second = run_agent_with_litellm(
                    "blast radius of CVE-2026-4421", "gemini/gemini-3.8-flash"
                )
            healthy.completion.assert_not_called()
            assert "token-service" in second.answer
        finally:
            gittrace_app._llm_auth_cooldown_until = 0.0

    def test_unrecognized_question_no_tools(self):
        resp = run_agent("tell me a joke")
        assert resp.tool_calls == []
        assert "couldn't identify" in resp.answer

    def test_greeting_gets_conversational_reply(self):
        # Small talk must not fall through to the tool-help message.
        resp = run_agent("hello")
        assert resp.tool_calls == []
        assert "couldn't identify" not in resp.answer
        assert "GitTrace" in resp.answer

    def test_greeting_with_name_still_conversational(self):
        resp = run_agent("hi from me")
        assert resp.tool_calls == []
        assert "GitTrace" in resp.answer

    def test_thanks_gets_conversational_reply(self):
        resp = run_agent("thanks!")
        assert resp.tool_calls == []
        assert "Anytime" in resp.answer

    def test_identity_question_lists_capabilities(self):
        resp = run_agent("who are you?")
        assert resp.tool_calls == []
        assert "blast radius" in resp.answer.lower()
        assert "couldn't identify" not in resp.answer

    def test_owner_for_function_outside_static_list(self, mock_graph):
        mock_graph.query.return_value = _fake_query_result(
            [["/user-service/users.js", "delete_user",
              "Priya Nair", "priya.nair@acme.com", "@priyan", ["user-service"]]]
        )
        with patch.object(gittrace_app, "_graph_names",
                          return_value=["delete_user", "process_payment"]) as names, \
             patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            # _graph_names is patched for both labels; the owner query still runs.
            resp = run_agent("who owns delete_user?")
        assert any(tc.name == "find_code_owner" for tc in resp.tool_calls)
        assert "Priya Nair" in resp.answer

    def test_owner_question_naming_only_the_cve(self, mock_graph):
        mock_graph.query.side_effect = [
            _fake_query_result([BLAST_ROW]),
            _fake_query_result([OWNER_ROW]),
        ]
        with patch.object(gittrace_app, "_graph_names", return_value=[]), \
             patch.object(gittrace_app, "_function_for_cve",
                          return_value="validate_token"), \
             patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            resp = run_agent("who owns the vulnerable function in CVE-2026-4421?")
        call = next(tc for tc in resp.tool_calls if tc.name == "find_code_owner")
        # Scoped by the CVE, so the owner lookup can't land on the other
        # validate_token.
        assert call.arguments == {"function_name": "validate_token",
                                  "cve_id": "CVE-2026-4421"}
        assert "Sarah Chen" in resp.answer

    def test_attack_path_without_start_defaults_to_gateway(self, mock_graph):
        mock_graph.query.side_effect = [
            _fake_query_result([[TOKEN_PY]]),
            _fake_query_result([[["Service:api-gateway", "Function:validate_token"], 1,
                                 TOKEN_PY]]),
        ]
        with patch.object(gittrace_app, "_graph_names", return_value=[]), \
             patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            resp = run_agent("shortest path to validate_token")
        call = next(
            tc for tc in resp.tool_calls if tc.name == "find_shortest_dependency_path"
        )
        assert call.arguments["start_service"] == "api-gateway"

    def test_greeting_does_not_skip_real_questions(self, mock_graph):
        # A greeting inside a real question must still dispatch tools.
        mock_graph.query.return_value = _fake_query_result(
            [OWNER_ROW]
        )
        with patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            resp = run_agent("hi, who owns validate_token?")
        assert any(tc.name == "find_code_owner" for tc in resp.tool_calls)
        assert "Sarah Chen" in resp.answer


# ---------------------------------------------------------------------------
# 4. LiteLLM agent loop (mocked LLM)
# ---------------------------------------------------------------------------

def _make_litellm_mock(first_turn, second_turn=None):
    """Build a fake litellm module whose completion() returns canned responses."""
    mock = MagicMock()

    def _completion(*args, **kwargs):
        # First call has tools= passed; second call does not.
        if kwargs.get("tools") is not None:
            return first_turn
        return second_turn

    mock.completion.side_effect = _completion
    return mock


def _tool_call_response(name: str, arguments: dict):
    """A litellm response containing one tool call."""
    tc = SimpleNamespace(
        id="call_1",
        function=SimpleNamespace(name=name, arguments=json.dumps(arguments)),
    )
    msg = SimpleNamespace(content=None, tool_calls=[tc])
    return SimpleNamespace(choices=[SimpleNamespace(message=msg)])


def _text_response(text: str):
    msg = SimpleNamespace(content=text, tool_calls=None)
    return SimpleNamespace(choices=[SimpleNamespace(message=msg)])


class TestAgentLoop:
    def test_first_turn_failure_falls_back_to_classifier(self, mock_graph):
        mock_graph.query.return_value = _fake_query_result(
            [BLAST_ROW]
        )
        failing = MagicMock()
        failing.completion.side_effect = RuntimeError("quota exceeded")
        with patch.dict(sys.modules, {"litellm": failing}), \
             patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            resp = run_agent_with_litellm("blast radius of CVE-2026-4421",
                                          "gemini/gemini-3.8-flash")
        assert "token-service" in resp.answer
        assert any(tc.name == "get_blast_radius" for tc in resp.tool_calls)

    def test_second_turn_success_returns_llm_answer(self, mock_graph):
        mock_graph.query.return_value = _fake_query_result(
            [BLAST_ROW]
        )
        first = _tool_call_response("get_blast_radius", {"cve_id": "CVE-2026-4421"})
        second = _text_response("CVE-2026-4421 is CRITICAL; token-service is impacted. Contact the owning team immediately.")
        fake = _make_litellm_mock(first, second)
        with patch.dict(sys.modules, {"litellm": fake}), \
             patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            resp = run_agent_with_litellm("blast radius of CVE-2026-4421",
                                          "gemini/gemini-3.8-flash")
        assert "token-service is impacted" in resp.answer
        assert resp.cve_id == "CVE-2026-4421"

    def test_second_turn_failure_falls_back_to_synthesized(self, mock_graph):
        mock_graph.query.return_value = _fake_query_result(
            [BLAST_ROW]
        )
        first = _tool_call_response("get_blast_radius", {"cve_id": "CVE-2026-4421"})
        second = MagicMock()
        second.completion.side_effect = RuntimeError("second turn blew up")
        with patch.dict(sys.modules, {"litellm": second}), \
             patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            resp = run_agent_with_litellm("blast radius of CVE-2026-4421",
                                          "gemini/gemini-3.8-flash")
        # Falls back to the keyword-synthesized answer but still returns data.
        assert "token-service" in resp.answer

    def test_second_turn_short_content_falls_back(self, mock_graph):
        mock_graph.query.return_value = _fake_query_result(
            [BLAST_ROW]
        )
        first = _tool_call_response("get_blast_radius", {"cve_id": "CVE-2026-4421"})
        second = _text_response("ok")  # shorter than 40 chars -> must fall back
        fake = _make_litellm_mock(first, second)
        with patch.dict(sys.modules, {"litellm": fake}), \
             patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            resp = run_agent_with_litellm("blast radius of CVE-2026-4421",
                                          "gemini/gemini-3.8-flash")
        assert "token-service" in resp.answer
        assert resp.answer != "ok"

    def test_no_tool_calls_returns_direct_content(self):
        first = _text_response("I can help with that, but no tool was needed.")
        fake = _make_litellm_mock(first)
        with patch.dict(sys.modules, {"litellm": fake}):
            resp = run_agent_with_litellm("hello there", "gemini/gemini-3.8-flash")
        assert resp.answer == "I can help with that, but no tool was needed."
        assert resp.tool_calls == []

    def test_unknown_tool_name_is_reported(self, mock_graph):
        first = _tool_call_response("nonexistent_tool", {"x": 1})
        second = _text_response("The requested tool does not exist in this system.")
        fake = _make_litellm_mock(first, second)
        with patch.dict(sys.modules, {"litellm": fake}), \
             patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            resp = run_agent_with_litellm("do something", "gemini/gemini-3.8-flash")
        assert any(tc.name == "nonexistent_tool" for tc in resp.tool_calls)

    def test_malformed_tool_args_do_not_crash(self, mock_graph):
        mock_graph.query.return_value = _fake_query_result(
            [BLAST_ROW]
        )
        tc = SimpleNamespace(
            id="call_1",
            function=SimpleNamespace(name="get_blast_radius", arguments="{not json"),
        )
        msg = SimpleNamespace(content=None, tool_calls=[tc])
        first = SimpleNamespace(choices=[SimpleNamespace(message=msg)])
        second = _text_response("Handled gracefully despite malformed arguments.")
        fake = _make_litellm_mock(first, second)
        with patch.dict(sys.modules, {"litellm": fake}), \
             patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            resp = run_agent_with_litellm("blast radius of CVE-2026-4421",
                                          "gemini/gemini-3.8-flash")
        assert isinstance(resp, AgentResponse)

    @pytest.mark.parametrize("raw, reason", [
        ('["CVE-2026-4421"]', "must be a JSON object, got list"),
        ('"CVE-2026-4421"', "must be a JSON object, got str"),
        ("null", "must be a JSON object, got NoneType"),
        ("{not json", "not valid JSON"),
        (["CVE-2026-4421"], "must be a JSON object, got list"),
    ])
    def test_non_object_tool_args_become_an_error(self, mock_graph, raw, reason):
        # Regression: a JSON array or string as arguments used to crash the
        # request (ToolCall validation / **args), and malformed JSON silently
        # turned into an empty argument dict.
        tc = SimpleNamespace(
            id="call_1",
            function=SimpleNamespace(name="get_blast_radius", arguments=raw),
        )
        first = SimpleNamespace(choices=[SimpleNamespace(
            message=SimpleNamespace(content=None, tool_calls=[tc]))])
        fake = _make_litellm_mock(first, _text_response("ok"))
        with patch.dict(sys.modules, {"litellm": fake}), \
             patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            resp = run_agent_with_litellm("blast radius of CVE-2026-4421",
                                          "gemini/gemini-3.8-flash")
        mock_graph.query.assert_not_called()
        assert resp.tool_calls[0].name == "get_blast_radius"
        assert resp.tool_calls[0].arguments == {}
        error = resp.tool_results[0].result["error"]
        assert "was not called" in error and reason in error, error
        assert error in resp.answer

    def test_llm_missing_cve_id_is_scoped_by_backend(self, mock_graph):
        # Regression guard for the duplicate-function-name bug: even when the
        # LLM calls find_shortest_dependency_path with name-only args, a CVE in
        # the question must scope the query to the affected instance
        # (token-service), not the auth-service copy.
        mock_graph.query.return_value = _fake_query_result(
            [[["Service:api-gateway", "Service:token-service",
               "File:/token-service/token.py", "Function:validate_token"], 3, TOKEN_PY]]
        )
        first = _tool_call_response(
            "find_shortest_dependency_path",
            {"start_service": "api-gateway", "target_function": "validate_token"},
        )
        second = _text_response(
            "The attacker reaches the vulnerable code in 3 hops."
        )
        fake = _make_litellm_mock(first, second)
        with patch.dict(sys.modules, {"litellm": fake}), \
             patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            resp = run_agent_with_litellm(
                "What's the shortest path from api-gateway to validate_token "
                "for CVE-2026-4421?",
                "gemini/gemini-3.8-flash",
            )
        call = [tc for tc in resp.tool_calls
                if tc.name == "find_shortest_dependency_path"][0]
        assert call.arguments.get("cve_id") == "CVE-2026-4421", call.arguments
        result = [tr for tr in resp.tool_results
                  if tr.name == "find_shortest_dependency_path"][0].result
        assert "Service:token-service" in result["path_trace"], result
        assert result["cve_id"] == "CVE-2026-4421", result

    def test_llm_owner_call_is_cve_scoped_by_backend(self, mock_graph):
        # Same guard for the owner tool: every tool flagged cve_scoped in the
        # registry gets the question's CVE when the LLM leaves it out.
        mock_graph.query.return_value = _fake_query_result([OWNER_ROW])
        first = _tool_call_response("find_code_owner", {"function_name": "validate_token"})
        second = _text_response("Sarah Chen owns the affected validate_token in token-service.")
        fake = _make_litellm_mock(first, second)
        with patch.dict(sys.modules, {"litellm": fake}), \
             patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            resp = run_agent_with_litellm(
                "Who should I notify about CVE-2026-4421?", "gemini/gemini-3.8-flash"
            )
        call = resp.tool_calls[0]
        assert call.arguments == {"function_name": "validate_token",
                                  "cve_id": "CVE-2026-4421"}


# ---------------------------------------------------------------------------
# 5. FastAPI endpoints
# ---------------------------------------------------------------------------

def _assert_ascii_safe(text: str) -> None:
    """Ensure an answer is safe to log to cp1252/conservative consoles.

    Gemini/LLM answers can contain Unicode arrows (U+2192) etc. that fail to
    encode under non-UTF-8 consoles. This check mirrors the old limitation so
    we keep it in guard only while accepting Unicode in the frontend (UTF-8).
    """
    # We no longer require ASCII — the frontend is UTF-8 and answers can
    # contain arrows from the model. Keep the check disabled but documented
    # so reviewers understand the tradeoff.
    pass


class TestEndpoints:
    def test_health(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json() == {"status": "ok"}

    def test_root_health(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert r.json() == {"status": "ok", "app": "GitTrace"}

    def test_tools(self, client):
        r = client.get("/tools")
        assert r.status_code == 200
        assert [t["function"]["name"] for t in r.json()["tools"]] == list(TOOL_REGISTRY)

    def test_demo(self, client):
        with patch.object(gittrace_app, "get_graph") as gg:
            g = MagicMock()
            g.query.side_effect = [
                _fake_query_result([BLAST_ROW]),
                _fake_query_result([[["Service:api-gateway", "Function:validate_token"], 1,
                                     TOKEN_PY]]),
                _fake_query_result([OWNER_ROW]),
            ]
            gg.return_value = g
            r = client.get("/demo")
        assert r.status_code == 200
        d = r.json()
        assert d["blast_radius"]["severity"] == "CRITICAL"
        assert d["attack_path"]["hop_count"] == 1
        assert d["code_owner"]["developer_name"] == "Sarah Chen"
        assert d["code_owner"]["file_path"] == TOKEN_PY
        # The demo's owner lookup is CVE-scoped, like its attack path.
        assert g.query.call_args_list[2][1]["params"]["cve_id"] == "CVE-2026-4421"

    def test_query_empty_question_400(self, client):
        r = client.post("/query", json={"question": ""})
        assert r.status_code == 400
        assert "question is required" in r.json()["detail"]

    def test_query_whitespace_question_400(self, client):
        r = client.post("/query", json={"question": "   \n\t "})
        assert r.status_code == 400
        assert "question is required" in r.json()["detail"]

    def test_query_missing_question_400(self, client):
        r = client.post("/query", json={})
        assert r.status_code == 400
        assert "question is required" in r.json()["detail"]

    def test_query_classifier_path(self, client, mock_graph):
        mock_graph.query.return_value = _fake_query_result(
            [BLAST_ROW]
        )
        failing = MagicMock()
        failing.completion.side_effect = RuntimeError("quota exceeded")
        with patch.dict(sys.modules, {"litellm": failing}), \
             patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            r = client.post("/query", json={"question": "blast radius of CVE-2026-4421"})
        assert r.status_code == 200
        d = r.json()
        assert d["cve_id"] == "CVE-2026-4421"
        assert "token-service" in d["answer"]

    def test_query_llm_path(self, client, mock_graph):
        mock_graph.query.return_value = _fake_query_result(
            [BLAST_ROW]
        )
        first = _tool_call_response("get_blast_radius", {"cve_id": "CVE-2026-4421"})
        second = _text_response("CVE-2026-4421 is CRITICAL; token-service is at risk and needs immediate attention.")
        fake = _make_litellm_mock(first, second)
        with patch.dict(sys.modules, {"litellm": fake}), \
             patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            r = client.post("/query", json={"question": "blast radius of CVE-2026-4421"})
        assert r.status_code == 200
        d = r.json()
        assert "token-service is at risk" in d["answer"]
        assert d["tool_calls"][0]["name"] == "get_blast_radius"
        assert len(d.get("tool_results", [])) == 1
        assert d["tool_results"][0]["name"] == "get_blast_radius"
        assert d["tool_results"][0]["result"]["cve_id"] == "CVE-2026-4421"


# ---------------------------------------------------------------------------
# 6. Tool registry: one entry drives every surface
# ---------------------------------------------------------------------------

def count_functions(service: str) -> dict:
    """A throwaway tool used to prove registration is a one-place change."""
    return {"service": service, "count": 3}


@pytest.fixture
def extra_tool(monkeypatch):
    tool = GraphTool(
        name="count_functions",
        func=count_functions,
        description="Count the functions a service defines.",
        parameters={
            "type": "object",
            "properties": {"service": {"type": "string"}},
            "required": ["service"],
            "additionalProperties": False,
        },
        label="function count",
        summarize=lambda d: f"{d['service']} defines {d['count']} functions.",
        plan=lambda ctx: ({"service": ctx.service_name}
                          if ctx.service_name and ctx.mentions(("how many",))
                          else None),
    )
    monkeypatch.setitem(TOOL_REGISTRY, tool.name, tool)
    return tool


class TestToolRegistry:
    def test_parameters_match_function_signatures(self):
        # The LLM schema is hand-written and the MCP schema is derived from the
        # function signature; keep the two in step.
        for name, tool in TOOL_REGISTRY.items():
            sig = inspect.signature(tool.func)
            params = tool.parameters
            assert set(params["properties"]) == set(sig.parameters), name
            required = {p.name for p in sig.parameters.values()
                        if p.default is inspect.Parameter.empty}
            assert set(params["required"]) == required, name

    def test_new_tool_reaches_schemas_and_tools_endpoint(self, extra_tool, client):
        assert "count_functions" in [s["function"]["name"] for s in tool_schemas()]
        names = [t["function"]["name"] for t in client.get("/tools").json()["tools"]]
        assert "count_functions" in names

    def test_new_tool_reaches_keyword_dispatch_and_synthesis(self, extra_tool):
        with patch.object(gittrace_app, "_graph_names", return_value=["api-gateway"]):
            resp = run_agent("how many functions are in api-gateway?")
        assert [tc.name for tc in resp.tool_calls] == ["count_functions"]
        assert resp.tool_calls[0].arguments == {"service": "api-gateway"}
        assert resp.answer == "[function count] api-gateway defines 3 functions."

    def test_new_tool_reaches_llm_dispatch(self, extra_tool):
        first = _tool_call_response("count_functions", {"service": "api-gateway"})
        fake = _make_litellm_mock(first, _text_response("ok"))
        with patch.dict(sys.modules, {"litellm": fake}):
            resp = run_agent_with_litellm("count", "gemini/gemini-3.8-flash")
        assert resp.tool_results[0].result == {"service": "api-gateway", "count": 3}
        assert "api-gateway defines 3 functions" in resp.answer

    def test_new_tool_reaches_mcp(self, extra_tool):
        import asyncio

        server = mcp_server.build_server()
        tools = {t.name: t for t in asyncio.run(server.list_tools())}
        assert set(tools) == {f"{n}_tool" for n in TOOL_REGISTRY}
        assert tools["count_functions_tool"].input_schema["required"] == ["service"]
        result = asyncio.run(server.call_tool("count_functions_tool", {"service": "x"}))
        assert result.is_error is False
        assert json.loads(result.content[0].text) == {"service": "x", "count": 3}


# ---------------------------------------------------------------------------
# 7. MCP server
# ---------------------------------------------------------------------------

class TestMCPServer:
    def test_tools_mirror_registry(self):
        import asyncio

        tools = asyncio.run(mcp_server.server.list_tools())
        assert [t.name for t in tools] == [f"{n}_tool" for n in TOOL_REGISTRY]
        owner = next(t for t in tools if t.name == "find_code_owner_tool")
        assert {"function_name", "file_path", "cve_id"} <= set(owner.input_schema["properties"])

    def test_nothing_is_written_to_stdout(self):
        # Under the stdio transport stdout *is* the protocol stream; a banner
        # printed before server.run() corrupts the first message.
        env = {**os.environ, "FALKORDB_HOST": os.environ.get("FALKORDB_HOST", "localhost")}
        code = (
            "import mcp_server\n"
            "mcp_server.server.run = lambda *a, **k: None\n"
            "mcp_server.main()\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", code],
            cwd=Path(__file__).resolve().parent,
            env=env, capture_output=True, text=True, timeout=120,
        )
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout == ""


# ---------------------------------------------------------------------------
# 8. Seed data integrity (no DB needed)
# ---------------------------------------------------------------------------

class TestSeedData:
    defined = {
        (path, name)
        for path, funcs in seed_graph.SERVICE_FILES.values()
        for name, _line, _entry in funcs
    }

    def test_function_definitions_are_unique_per_file(self):
        pairs = [(path, name) for path, funcs in seed_graph.SERVICE_FILES.values()
                 for name, _line, _entry in funcs]
        assert len(pairs) == len(set(pairs))

    def test_every_call_edge_targets_defined_functions(self):
        # Regression: calls(tp, "refresh_token", ...) named a function
        # token-service did not define, so MATCH ... CREATE silently made
        # no edge.
        for src_path, src, dst_path, dst in seed_graph.CALL_EDGES:
            assert (src_path, src) in self.defined, (src_path, src)
            assert (dst_path, dst) in self.defined, (dst_path, dst)
        assert ("/token-service/token.py", "refresh_token",
                "/token-service/token.py", "validate_token") in seed_graph.CALL_EDGES

    def test_cves_and_endpoints_target_defined_functions(self):
        for cve_id, _sev, _desc, path, name in seed_graph.CVES:
            assert (path, name) in self.defined, cve_id
        for method, route, path, name in seed_graph.ENDPOINTS:
            assert (path, name) in self.defined, (method, route)

    def test_people_and_services_exist(self):
        services = {name for name, *_ in seed_graph.SERVICES}
        developers = {name for name, *_ in seed_graph.DEVELOPERS}
        assert set(seed_graph.SERVICE_FILES) == services
        for dev, svc in seed_graph.OWNERSHIP + seed_graph.AUTHORED:
            assert dev in developers and svc in services
        for child, parent in seed_graph.DEPENDS:
            assert child in services and parent in services

    def test_link_rejects_an_edge_that_matched_nothing(self):
        g = MagicMock()
        g.query.return_value = SimpleNamespace(relationships_created=0)
        with pytest.raises(RuntimeError, match="expected 1 relationship"):
            seed_graph.link(g, "MATCH (a), (b) CREATE (a)-[:CALLS]->(b)", {})
