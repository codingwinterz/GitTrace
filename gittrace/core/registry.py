"""
gittrace.core.registry — the one list of graph tools.

One entry per tool. The LiteLLM schemas, the keyword classifier, answer
synthesis and the MCP server all read TOOL_REGISTRY, so adding a tool is a
single new entry here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from gittrace.core.question import QuestionContext
from gittrace.core.tools import (
    find_code_owner,
    find_shortest_dependency_path,
    get_blast_radius,
)


@dataclass(frozen=True)
class GraphTool:
    name: str
    func: Callable[..., dict[str, Any]]
    description: str
    parameters: dict[str, Any]
    # Prefix used in synthesized answers, e.g. "[blast radius] ...".
    label: str
    # Renders a successful result as one sentence of the synthesized answer.
    summarize: Callable[[dict[str, Any]], str]
    # Keyword classifier: the arguments to call the tool with for a
    # question, or None when the question doesn't call for this tool.
    plan: Callable[[QuestionContext], dict[str, Any] | None]
    # When the question carries a CVE and the LLM omits cve_id, scope the call
    # to the CVE's affected function rather than trusting a bare name.
    cve_scoped: bool = False

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


_PATH_KEYWORDS = ("path", "shortest", "attack", "entry", "reach", "how does")
_OWNER_KEYWORDS = ("owner", "notify", "contact", "who", "slack", "email")

_CVE_ID_PARAM = {
    "type": "string",
    "description": (
        "Optional. When supplied, the tool resolves the exact Function node "
        "the CVE AFFECTS, so it points at the same function the blast-radius "
        "tool reports. Recommended for CVE-driven questions."
    ),
}


def _plan_blast_radius(ctx: QuestionContext) -> dict[str, Any] | None:
    return {"cve_id": ctx.cve_id} if ctx.cve_id else None


def _plan_shortest_path(ctx: QuestionContext) -> dict[str, Any] | None:
    if not ctx.mentions(_PATH_KEYWORDS) or not ctx.target_function:
        return None
    args: dict[str, Any] = {
        "start_service": ctx.service_name or "api-gateway",
        "target_function": ctx.target_function,
    }
    if ctx.cve_id:
        args["cve_id"] = ctx.cve_id
    return args


def _plan_code_owner(ctx: QuestionContext) -> dict[str, Any] | None:
    if not ctx.mentions(_OWNER_KEYWORDS) or not ctx.target_function:
        return None
    args: dict[str, Any] = {"function_name": ctx.target_function}
    if ctx.cve_id:
        args["cve_id"] = ctx.cve_id
    return args


def _summarize_blast_radius(data: dict[str, Any]) -> str:
    sev = data.get("severity") or "unknown"
    affected = data.get("affected_function_ids") or []
    services = data.get("impacted_services") or []
    funcs = data.get("impacted_functions") or []
    count = data.get("service_count", 0)
    return (
        f"CVE {data.get('cve_id')} is {sev} and affects "
        f"{', '.join(affected) or 'an unknown function'}. "
        f"{count} service(s) impacted: {', '.join(services) or 'none'}. "
        f"Upstream callers: {', '.join(funcs) or 'none'}."
    )


def _summarize_shortest_path(data: dict[str, Any]) -> str:
    trace_line = " -> ".join(data.get("path_trace") or [])
    hops = data.get("hop_count")
    return (
        f"From {data.get('start_service')} to "
        f"{data.get('target_function')}: {trace_line} "
        f"({hops} hop{'s' if hops != 1 else ''})."
    )


def _summarize_code_owner(data: dict[str, Any]) -> str:
    contact = data.get("developer_name") or "unknown"
    if data.get("email"):
        contact += f" ({data['email']})"
    if data.get("slack"):
        contact += f", {data['slack']}"
    where = f" ({data['file_path']})" if data.get("file_path") else ""
    owned = data.get("owned_services") or []
    return (
        f"{data.get('function_name')}{where} is owned by "
        f"{contact}. Also owns: {', '.join(owned) or 'none'}."
    )


TOOL_REGISTRY: dict[str, GraphTool] = {
    tool.name: tool for tool in (
        GraphTool(
            name="get_blast_radius",
            func=get_blast_radius,
            description=(
                "Find every function that calls the code a CVE affects "
                "(directly or transitively) and the services they live in. "
                "Call this when asked about blast radius, impact, or what "
                "breaks if a vulnerable function is taken offline."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "cve_id": {
                        "type": "string",
                        "description": "CVE identifier, e.g. 'CVE-2026-4421'.",
                    },
                },
                "required": ["cve_id"],
                "additionalProperties": False,
            },
            label="blast radius",
            summarize=_summarize_blast_radius,
            plan=_plan_blast_radius,
        ),
        GraphTool(
            name="find_shortest_dependency_path",
            func=find_shortest_dependency_path,
            description=(
                "Use FalkorDB's native shortestPath to trace how an attacker "
                "reaches a specific vulnerable Function node from a public-facing "
                "service. The target is scoped by the CVE's AFFECTS edge when a "
                "cve_id is supplied (recommended for CVE-driven questions), or by "
                "target_file_path when the exact instance is known. A bare name "
                "defined in several files is reported as ambiguous."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "start_service": {
                        "type": "string",
                        "description": "Public-facing service name, e.g. 'api-gateway'.",
                    },
                    "target_function": {
                        "type": "string",
                        "description": "Function name, e.g. 'validate_token'.",
                    },
                    "cve_id": _CVE_ID_PARAM,
                    "target_file_path": {
                        "type": "string",
                        "description": "Optional. When supplied, the tool matches the exact Function node defined by that file path (e.g. '/token-service/token.py'). Use when the file context is known.",
                    },
                },
                "required": ["start_service", "target_function"],
                "additionalProperties": False,
            },
            label="attack path",
            summarize=_summarize_shortest_path,
            plan=_plan_shortest_path,
            cve_scoped=True,
        ),
        GraphTool(
            name="find_code_owner",
            func=find_code_owner,
            description=(
                "Find the developer who owns/authored the vulnerable "
                "code for alerting. Call this when asked who owns the "
                "code, who to notify, or the contact info for a function. "
                "A bare name defined in several files is reported as "
                "ambiguous; pass cve_id or file_path to pick one."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "function_name": {
                        "type": "string",
                        "description": "Function name, e.g. 'validate_token'.",
                    },
                    "cve_id": _CVE_ID_PARAM,
                    "file_path": {
                        "type": "string",
                        "description": "Optional. The file that defines the function (e.g. '/token-service/token.py').",
                    },
                },
                "required": ["function_name"],
                "additionalProperties": False,
            },
            label="code owner",
            summarize=_summarize_code_owner,
            plan=_plan_code_owner,
            cve_scoped=True,
        ),
    )
}


def tool_schemas() -> list[dict[str, Any]]:
    """Return OpenAI-format tool definitions for every registered tool."""
    return [tool.schema() for tool in TOOL_REGISTRY.values()]


def call_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    """Run a registered tool, turning any failure into an error result."""
    tool = TOOL_REGISTRY.get(name)
    if tool is None:
        return {"error": f"Unknown tool: {name}"}
    try:
        return tool.func(**args)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"Tool '{name}' raised: {exc}"}
