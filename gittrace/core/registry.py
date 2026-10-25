"""
gittrace.core.registry — the one list of graph tools.

The MCP server and the agent both read TOOL_REGISTRY, so adding a tool is a
single new entry here. `parameters` is the JSON schema the agent sends to the
model; the MCP server derives its schema from the function signature, and the
offline suite checks that the two agree.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from gittrace.core.tools import blast_radius, finding_owner, list_findings, trace_attack_path
from gittrace.rules.base import SEVERITIES


@dataclass(frozen=True)
class GraphTool:
    name: str
    func: Callable[..., dict[str, Any]]
    description: str
    parameters: dict[str, Any]

    def schema(self) -> dict[str, Any]:
        """OpenAI-format tool definition for LiteLLM function calling."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


_PROJECT = {
    "type": "string",
    "description": "Path to the project folder that `gittrace scan` was run on.",
}
_FINDING = {
    "type": "string",
    "description": "A finding id (path.py::line::column, as list_findings returns it) "
                   "or path.py:line relative to the project.",
}
_DEPTH = {
    "type": "integer",
    "description": "Maximum number of CALLS hops to follow (1-50, default 10).",
}


TOOL_REGISTRY: dict[str, GraphTool] = {
    tool.name: tool for tool in (
        GraphTool(
            name="list_findings",
            func=list_findings,
            description=(
                "List the vulnerabilities the last `gittrace scan` found in a project, most "
                "severe first, with their location, reachability from endpoints, blast "
                "radius and owner."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "project": _PROJECT,
                    "min_severity": {"type": "string", "enum": list(SEVERITIES),
                                     "description": "Lowest severity to include (default info)."},
                    "rule_id": {"type": "string",
                                "description": "Only this rule, e.g. GT-SQLI-001."},
                },
                "required": ["project"],
                "additionalProperties": False,
            },
        ),
        GraphTool(
            name="trace_attack_path",
            func=trace_attack_path,
            description=(
                "Trace how a finding is reached: the shortest path from each endpoint "
                "(HANDLED_BY, then CALLS) to the vulnerable function, unauthenticated "
                "endpoints first."
            ),
            parameters={
                "type": "object",
                "properties": {"project": _PROJECT, "finding": _FINDING, "depth": _DEPTH},
                "required": ["project", "finding"],
                "additionalProperties": False,
            },
        ),
        GraphTool(
            name="blast_radius",
            func=blast_radius,
            description=(
                "The blast radius of a function: every function that calls it directly or "
                "transitively, and every endpoint that can reach it."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "project": _PROJECT,
                    "function_id": {"type": "string",
                                    "description": "Function id, e.g. app/db.py::Repo.get_user."},
                    "depth": _DEPTH,
                },
                "required": ["project", "function_id"],
                "additionalProperties": False,
            },
        ),
        GraphTool(
            name="finding_owner",
            func=finding_owner,
            description=(
                "Who last changed a finding's line, from git blame (author, email, commit), "
                "when the project is a git repository."
            ),
            parameters={
                "type": "object",
                "properties": {"project": _PROJECT, "finding": _FINDING},
                "required": ["project", "finding"],
                "additionalProperties": False,
            },
        ),
    )
}


def tool_schemas(exclude: tuple[str, ...] = ()) -> list[dict[str, Any]]:
    """OpenAI-format tool definitions for every registered tool, without the
    parameters in `exclude` (the agent supplies `project` itself)."""
    schemas = []
    for tool in TOOL_REGISTRY.values():
        schema = tool.schema()
        params = dict(schema["function"]["parameters"])      # never edit the registry's copy
        params["properties"] = {k: v for k, v in params["properties"].items() if k not in exclude}
        params["required"] = [k for k in params["required"] if k not in exclude]
        schema["function"] = {**schema["function"], "parameters": params}
        schemas.append(schema)
    return schemas


def call_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    """Run a registered tool, turning any failure into an error result."""
    tool = TOOL_REGISTRY.get(name)
    if tool is None:
        return {"error": f"Unknown tool: {name}"}
    try:
        return tool.func(**args)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"Tool '{name}' raised: {type(exc).__name__}: {exc}"}
