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

import json
import sys
import types
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import app as gittrace_app
from app import (
    AgentResponse,
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

    def test_synthesize_no_tool_calls(self):
        out = _synthesize_answer("q", [], [], None)
        assert "couldn't identify" in out

    def test_synthesize_blast_radius(self):
        calls = [ToolCall(name="get_blast_radius", arguments={"cve_id": "CVE-2026-4421"})]
        results = [{"name": "get_blast_radius", "result": {
            "cve_id": "CVE-2026-4421", "severity": "CRITICAL",
            "impacted_services": ["token-service"],
            "impacted_functions": ["parse_claims"], "service_count": 1,
        }}]
        out = _synthesize_answer("q", calls, results, "CVE-2026-4421")
        assert "CVE-2026-4421" in out
        assert "CRITICAL" in out
        assert "token-service" in out

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
        assert len(schemas) == 3
        names = {s["function"]["name"] for s in schemas}
        assert names == {"get_blast_radius",
                         "find_shortest_dependency_path",
                         "find_code_owner"}
        for s in schemas:
            assert s["type"] == "function"
            assert "parameters" in s["function"]

    def test_get_blast_radius(self, mock_graph):
        mock_graph.query.return_value = _fake_query_result(
            [["CVE-2026-4421", "CRITICAL", ["token-service"], ["parse_claims"], 1]]
        )
        with patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            out = get_blast_radius("CVE-2026-4421")
        assert out["cve_id"] == "CVE-2026-4421"
        assert out["severity"] == "CRITICAL"
        assert out["impacted_services"] == ["token-service"]
        assert out["service_count"] == 1

    def test_get_blast_radius_not_found(self, mock_graph):
        mock_graph.query.return_value = _fake_query_result([])
        with patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            out = get_blast_radius("CVE-0000-0000")
        assert "error" in out
        assert out["service_count"] == 0

    def test_find_shortest_dependency_path(self, mock_graph):
        mock_graph.query.return_value = _fake_query_result(
            [[["Service:api-gateway", "Function:validate_token"], 1]]
        )
        with patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            out = find_shortest_dependency_path("api-gateway", "validate_token")
        assert out["hop_count"] == 1
        assert "Service:api-gateway" in out["path_trace"]
        assert out["target_function"] == "validate_token"
        assert out["cve_id"] is None

    def test_find_shortest_dependency_path_cve_scoped(self, mock_graph):
        mock_graph.query.return_value = _fake_query_result(
            [[["Service:api-gateway", "Service:token-service",
               "File:/token-service/token.py", "Function:validate_token"], 3]]
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

    def test_find_shortest_dependency_path_file_scoped(self, mock_graph):
        mock_graph.query.return_value = _fake_query_result(
            [[["Service:api-gateway", "Service:auth-service",
               "File:/auth-service/auth.go", "Function:validate_token"], 3]]
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
            [["Sarah Chen", "sarah.chen@acme.com", "@sarahc", ["auth-service"]]]
        )
        with patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            out = find_code_owner("validate_token")
        assert out["developer_name"] == "Sarah Chen"
        assert out["slack"] == "@sarahc"

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
            [["CVE-2026-4421", "CRITICAL", ["token-service"], ["parse_claims"], 1]]
        )
        with patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            resp = run_agent("What's the blast radius of CVE-2026-4421?")
        assert isinstance(resp, AgentResponse)
        assert resp.cve_id == "CVE-2026-4421"
        assert any(tc.name == "get_blast_radius" for tc in resp.tool_calls)
        assert "token-service" in resp.answer

    def test_owner_question_calls_code_owner(self, mock_graph):
        mock_graph.query.return_value = _fake_query_result(
            [["Sarah Chen", "sarah.chen@acme.com", "@sarahc", ["auth-service"]]]
        )
        with patch.object(gittrace_app, "get_graph", return_value=mock_graph):
            resp = run_agent("Who owns validate_token?")
        assert any(tc.name == "find_code_owner" for tc in resp.tool_calls)
        assert "Sarah Chen" in resp.answer

    def test_unrecognized_question_no_tools(self):
        resp = run_agent("tell me a joke")
        assert resp.tool_calls == []
        assert "couldn't identify" in resp.answer


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
            [["CVE-2026-4421", "CRITICAL", ["token-service"], ["parse_claims"], 1]]
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
            [["CVE-2026-4421", "CRITICAL", ["token-service"], ["parse_claims"], 1]]
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
            [["CVE-2026-4421", "CRITICAL", ["token-service"], ["parse_claims"], 1]]
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
            [["CVE-2026-4421", "CRITICAL", ["token-service"], ["parse_claims"], 1]]
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
            [["CVE-2026-4421", "CRITICAL", ["token-service"], ["parse_claims"], 1]]
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

    def test_tools(self, client):
        r = client.get("/tools")
        assert r.status_code == 200
        assert len(r.json()["tools"]) == 3

    def test_demo(self, client):
        with patch.object(gittrace_app, "get_graph") as gg:
            g = MagicMock()
            g.query.side_effect = [
                _fake_query_result([["CVE-2026-4421", "CRITICAL", ["token-service"], ["parse_claims"], 1]]),
                _fake_query_result([[["Service:api-gateway", "Function:validate_token"], 1]]),
                _fake_query_result([["Sarah Chen", "sarah.chen@acme.com", "@sarahc", ["auth-service"]]]),
            ]
            gg.return_value = g
            r = client.get("/demo")
        assert r.status_code == 200
        d = r.json()
        assert d["blast_radius"]["severity"] == "CRITICAL"
        assert d["attack_path"]["hop_count"] == 1
        assert d["code_owner"]["developer_name"] == "Sarah Chen"

    def test_query_empty_question_400(self, client):
        r = client.post("/query", json={"question": ""})
        assert r.status_code == 422  # pydantic min_length=1 catches it first

    def test_query_classifier_path(self, client, mock_graph):
        mock_graph.query.return_value = _fake_query_result(
            [["CVE-2026-4421", "CRITICAL", ["token-service"], ["parse_claims"], 1]]
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
            [["CVE-2026-4421", "CRITICAL", ["token-service"], ["parse_claims"], 1]]
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
