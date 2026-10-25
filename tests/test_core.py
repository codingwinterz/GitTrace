"""
test_core.py — offline tests for gittrace.core's tool layer (no database, no API key).

Covers:
  1. the tool registry: one entry drives the LLM schemas and the MCP server
  2. the tools' error handling with the database mocked out
  3. the MCP server: tools mirror the registry; nothing is written to stdout
  4. the generic agent loop against a mocked LiteLLM

The tools' Cypher runs unmocked in tests/test_scan_integration.py.

Run:  pytest tests/test_core.py -v
"""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from gittrace import mcp_server
from gittrace.core import agent, tools
from gittrace.core.agent import AgentError, run_agent
from gittrace.core.models import AgentResponse
from gittrace.core.registry import TOOL_REGISTRY, GraphTool, call_tool, tool_schemas
from gittrace.graph import connection

REPO_ROOT = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# 1. Registry
# ---------------------------------------------------------------------------

class TestRegistry:
    def test_the_four_tools(self):
        assert list(TOOL_REGISTRY) == [
            "list_findings", "trace_attack_path", "blast_radius", "finding_owner",
        ]

    def test_parameters_match_function_signatures(self):
        # The LLM schema is hand-written and the MCP schema is derived from the
        # function signature; keep the two in step.
        for name, tool in TOOL_REGISTRY.items():
            sig = inspect.signature(tool.func)
            assert set(tool.parameters["properties"]) == set(sig.parameters), name
            required = {p.name for p in sig.parameters.values()
                        if p.default is inspect.Parameter.empty}
            assert set(tool.parameters["required"]) == required, name

    def test_schemas_can_leave_out_project(self):
        for schema in tool_schemas(exclude=("project",)):
            params = schema["function"]["parameters"]
            assert "project" not in params["properties"]
            assert "project" not in params["required"]
        # ...without touching the registry's own copy
        assert all("project" in t.parameters["properties"] for t in TOOL_REGISTRY.values())

    def test_unknown_tool(self):
        assert call_tool("nope", {}) == {"error": "Unknown tool: nope"}

    def test_a_crashing_tool_becomes_an_error(self, monkeypatch):
        def boom(project: str) -> dict:
            raise KeyError("x")
        monkeypatch.setitem(TOOL_REGISTRY, "boom", GraphTool("boom", boom, "d", {
            "type": "object", "properties": {"project": {}}, "required": ["project"]}))
        assert call_tool("boom", {"project": "."}) == {"error": "Tool 'boom' raised: KeyError: 'x'"}


# ---------------------------------------------------------------------------
# 2. Tools without a database
# ---------------------------------------------------------------------------

@pytest.fixture
def no_graphs():
    db = MagicMock()
    db.list_graphs.return_value = []
    with patch.object(connection, "get_db", return_value=db):
        yield db


class TestToolErrors:
    def test_unscanned_project(self, no_graphs, tmp_path):
        out = tools.list_findings(str(tmp_path))
        assert "run `gittrace scan" in out["error"]
        no_graphs.select_graph.assert_not_called()

    def test_bad_severity(self, no_graphs):
        assert "min_severity must be one of" in tools.list_findings(".", min_severity="urgent")["error"]

    @pytest.mark.parametrize("finding", ["app.py", "app.py:x", ":12"])
    def test_bad_finding_reference(self, finding, tmp_path):
        db = MagicMock()
        from gittrace.graph import store
        db.list_graphs.return_value = [store.graph_name_for(tmp_path)]
        with patch.object(connection, "get_db", return_value=db):
            out = tools.trace_attack_path(str(tmp_path), finding)
        assert "expected a finding id" in out["error"]

    def test_bad_depth(self, tmp_path):
        db = MagicMock()
        from gittrace.graph import store
        db.list_graphs.return_value = [store.graph_name_for(tmp_path)]
        with patch.object(connection, "get_db", return_value=db):
            out = tools.blast_radius(str(tmp_path), "a.py::f", depth=99)
        assert "depth must be an integer from 1 to 50" in out["error"]


# ---------------------------------------------------------------------------
# 3. MCP server
# ---------------------------------------------------------------------------

class TestMCPServer:
    def test_tools_mirror_registry(self):
        listed = asyncio.run(mcp_server.server.list_tools())
        assert [t.name for t in listed] == [f"{n}_tool" for n in TOOL_REGISTRY]
        by_name = {t.name: t for t in listed}
        assert by_name["trace_attack_path_tool"].input_schema["required"] == ["project", "finding"]
        assert set(by_name["list_findings_tool"].input_schema["properties"]) == {
            "project", "min_severity", "rule_id"}

    def test_tool_errors_reach_the_client(self, no_graphs, tmp_path):
        result = asyncio.run(mcp_server.server.call_tool(
            "list_findings_tool", {"project": str(tmp_path)}))
        assert "run `gittrace scan" in json.loads(result.content[0].text)["error"]

    def test_nothing_is_written_to_stdout(self):
        # Under the stdio transport stdout *is* the protocol stream.
        env = {**os.environ, "FALKORDB_HOST": os.environ.get("FALKORDB_HOST", "localhost")}
        code = (
            "import sys\n"
            "from gittrace import mcp_server\n"
            "mcp_server.server.run = lambda *a, **k: None\n"
            "mcp_server.main()\n"
            "assert 'fastapi' not in sys.modules, 'mcp_server imported fastapi'\n"
        )
        proc = subprocess.run([sys.executable, "-c", code], cwd=REPO_ROOT, env=env,
                              capture_output=True, text=True, timeout=120)
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout == ""


# ---------------------------------------------------------------------------
# 4. Agent loop (mocked LLM)
# ---------------------------------------------------------------------------

def _fake_litellm(first, second=None):
    fake = MagicMock()
    fake.completion.side_effect = lambda **kw: first if kw.get("tools") is not None else second
    return fake


def _tool_call(name: str, arguments):
    raw = arguments if isinstance(arguments, str) else json.dumps(arguments)
    tc = SimpleNamespace(id="c1", function=SimpleNamespace(name=name, arguments=raw))
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=None, tool_calls=[tc]))])


def _text(text: str):
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=text, tool_calls=None))])


class TestAgent:
    def test_project_is_supplied_by_the_agent(self, monkeypatch):
        seen = {}

        def fake_list(project: str, min_severity: str = "info", rule_id: str | None = None):
            seen.update(project=project, min_severity=min_severity)
            return {"count": 2}
        monkeypatch.setitem(TOOL_REGISTRY, "list_findings",
                            GraphTool("list_findings", fake_list, "d", TOOL_REGISTRY["list_findings"].parameters))
        fake = _fake_litellm(_tool_call("list_findings", {"min_severity": "high"}),
                             _text("There are 2 high findings."))
        with patch.dict(sys.modules, {"litellm": fake}):
            resp = run_agent("how many high findings?", "/proj", "ollama/x")
        assert seen == {"project": "/proj", "min_severity": "high"}
        assert resp.answer == "There are 2 high findings."
        assert resp.tool_results[0].result == {"count": 2}
        first_call = fake.completion.call_args_list[0].kwargs
        assert all("project" not in t["function"]["parameters"]["properties"]
                   for t in first_call["tools"])

    @pytest.mark.parametrize("raw, reason", [
        ('["x"]', "must be a JSON object, got list"),
        ("null", "must be a JSON object, got NoneType"),
        ("{not json", "not valid JSON"),
    ])
    def test_bad_tool_arguments_are_reported_not_run(self, raw, reason):
        fake = _fake_litellm(_tool_call("list_findings", raw), _text("ok"))
        with patch.dict(sys.modules, {"litellm": fake}):
            resp = run_agent("q", "/proj", "ollama/x")
        error = resp.tool_results[0].result["error"]
        assert "was not called" in error and reason in error

    def test_no_tool_call_returns_the_text(self):
        with patch.dict(sys.modules, {"litellm": _fake_litellm(_text("hello"))}):
            resp = run_agent("hi", "/proj", "ollama/x")
        assert isinstance(resp, AgentResponse) and resp.answer == "hello" and resp.tool_calls == []

    @pytest.mark.parametrize("turn", ["first", "second"])
    def test_llm_failures_are_raised(self, turn):
        fake = MagicMock()

        def completion(**kw):
            if turn == "first" or kw.get("tools") is None:
                raise TimeoutError("model not loaded")
            return _tool_call("list_findings", {})
        fake.completion.side_effect = completion
        with patch.dict(sys.modules, {"litellm": fake}), \
             patch.object(agent, "call_tool", return_value={"count": 0}), \
             pytest.raises(AgentError, match="TimeoutError: model not loaded"):
            run_agent("q", "/proj", "ollama/x")
