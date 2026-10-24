"""
app.py — GitTrace Phase 3

FastAPI backend + LLM agent loop. The agent receives a natural-language
security question (e.g. a CVE alert) and calls one or more of the FalkorDB
graph tools in TOOL_REGISTRY:

  - get_blast_radius(cve_id)
  - find_shortest_dependency_path(start_service, target_function,
                                  *, target_file_path=None, cve_id=None)
  - find_code_owner(function_name, *, file_path=None, cve_id=None)

Stack: FastAPI + LiteLLM (gemini-2.0-flash) + falkordb 1.8.0 Python client.

The falkordb 1.8.0 API used here:
    FalkorDB(host, port, username, password).connection.ping()
    db.select_graph(name) -> Graph
    graph.query(cypher, params) -> QueryResult
    QueryResult.result_set -> list of row-lists

shortestPath is only supported in WITH or RETURN clauses in FalkorDB
(not directly in MATCH), so the Cypher below uses WITH ... shortestPath ... AS p.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import Any, Callable

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

load_dotenv(Path(__file__).resolve().parent / ".env")

# LiteLLM reads GEMINI_API_KEY automatically for gemini/* models; copy from our env name.
if os.environ.get("Gemini_API_Key") and not os.environ.get("GEMINI_API_KEY"):
    os.environ["GEMINI_API_KEY"] = os.environ["Gemini_API_Key"]

from utils import get_graph  # noqa: E402


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class QueryRequest(BaseModel):
    # Deliberately not min_length=1: an empty/missing question is a client
    # mistake we report as a clean 400 from the endpoint, not a raw 422 from
    # Pydantic validation.
    question: str | None = Field(
        None, max_length=4000,
        description="Natural-language security question / CVE alert.",
    )
    model: str | None = Field(
        None,
        description="LiteLLM model string. Defaults to LITELLM_MODEL env or "
                    "'gemini-2.0-flash'.",
    )


class ToolCall(BaseModel):
    name: str
    arguments: dict[str, Any]


class ToolResult(BaseModel):
    name: str
    arguments: dict[str, Any]
    result: dict[str, Any]


class AgentResponse(BaseModel):
    answer: str
    tool_calls: list[ToolCall]
    tool_results: list[ToolResult] = Field(default_factory=list)
    cve_id: str | None = None


# ---------------------------------------------------------------------------
# Graph tools (the FalkorDB-backed capabilities from SPEC.md)
# ---------------------------------------------------------------------------
#
# Function names are not unique (validate_token and refresh_token exist in two
# services), so a Function is only ever identified by its (file path, name)
# pair, or through a CVE's AFFECTS edge. Results carry that pair as
# "file_path::name" wherever a bare name would be ambiguous.

def _qualified(file_path: str, function_name: str) -> str:
    return f"{file_path}::{function_name}"


def _function_files(g, function_name: str) -> list[str]:
    """Paths of every File that defines a Function with exactly this name."""
    rows = g.query(
        "MATCH (file:File)-[:DEFINES]->(f:Function {name: $name}) "
        "RETURN DISTINCT file.path AS path ORDER BY path",
        params={"name": function_name},
    ).result_set
    return [str(r[0]) for r in rows if r and r[0]]


def _ambiguous_error(function_name: str, file_paths: list[str]) -> str:
    return (
        f"'{function_name}' is defined in {len(file_paths)} files "
        f"({', '.join(file_paths)}). Pass file_path or cve_id to pick one."
    )


def get_blast_radius(cve_id: str) -> dict[str, Any]:
    """Find every function that can reach the code a CVE affects, and the
    services those callers live in.

    The blast radius is upstream: if the vulnerable function is exploited or
    taken offline, the functions that call it (directly or transitively) are
    the ones that break or carry the attack further. What the vulnerable
    function itself calls is not at risk from it.

    Cypher:
        MATCH (c:CVE {id: $cve_id})-[:AFFECTS]->(f:Function)<-[:DEFINES]-(file:File)
        OPTIONAL MATCH (caller:Function)-[:CALLS*1..5]->(f) WHERE caller <> f
        OPTIONAL MATCH (caller)<-[:DEFINES]-(caller_file:File)
        OPTIONAL MATCH (caller_file)<-[:CONTAINS]-(s:Service)
        RETURN ... collect(DISTINCT s.name), collect(DISTINCT caller.name) ...
    """
    g = get_graph()

    cypher = """
    MATCH (c:CVE {id: $cve_id})-[:AFFECTS]->(f:Function)<-[:DEFINES]-(file:File)
    OPTIONAL MATCH (caller:Function)-[:CALLS*1..5]->(f)
    WHERE caller <> f
    OPTIONAL MATCH (caller)<-[:DEFINES]-(caller_file:File)
    OPTIONAL MATCH (caller_file)<-[:CONTAINS]-(s:Service)
    RETURN
        c.id AS cve_id,
        c.severity AS severity,
        collect(DISTINCT s.name) AS impacted_services,
        collect(DISTINCT caller.name) AS impacted_functions,
        count(DISTINCT s) AS service_count,
        collect(DISTINCT file.path + '::' + f.name) AS affected_function_ids,
        collect(DISTINCT caller_file.path + '::' + caller.name) AS impacted_function_ids
    """
    result = g.query(cypher, params={"cve_id": cve_id})
    rs = result.result_set
    if not rs:
        return {
            "cve_id": cve_id, "severity": None,
            "affected_function_ids": [],
            "impacted_services": [], "impacted_functions": [],
            "impacted_function_ids": [],
            "service_count": 0,
            "error": f"CVE '{cve_id}' not found in the graph.",
        }

    row = rs[0]

    def _sorted(values) -> list[str]:
        # collect() returns rows in graph-traversal order, which FalkorDB does
        # not guarantee to be stable. Sort so the contract is deterministic.
        return sorted(str(x) for x in (values or []) if x)

    return {
        "cve_id": str(row[0]) if row[0] else cve_id,
        "severity": str(row[1]) if row[1] else None,
        "affected_function_ids": _sorted(row[5]),
        "impacted_services": _sorted(row[2]),
        "impacted_functions": _sorted(row[3]),
        "impacted_function_ids": _sorted(row[6]),
        "service_count": int(row[4]) if row[4] is not None else 0,
    }


def find_shortest_dependency_path(
    start_service: str,
    target_function: str,
    *,
    target_file_path: str | None = None,
    cve_id: str | None = None,
) -> dict[str, Any]:
    """Use FalkorDB's native shortestPath (via WITH) to trace how an
    attacker reaches the vulnerable code from a public-facing service.

    The target is scoped to a single Function *instance*, not any function
    sharing its name. If `cve_id` is supplied, the tool derives the exact
    affected Function node from the CVE's AFFECTS edge — the same source
    get_blast_radius uses — so the attack-path and blast-radius tools are
    guaranteed to point at the same vulnerable code. If `target_file_path`
    is supplied, the query matches the Function defined by that file.

    With neither, the name must identify exactly one Function in the graph.
    A name defined in several files (validate_token) is reported as
    ambiguous, with the candidate files, instead of silently resolving to
    whichever copy happens to be closest.

    Implementation note: FalkorDB only supports shortestPath in WITH or
    RETURN clauses, so the Cypher uses WITH ... shortestPath ... AS p.
    The path must traverse CONTAINS (Service->File), DEFINES (File->
    Function), DEPENDS_ON (Service->Service) because a Function lives
    inside a File inside a Service, and services depend on other services.
    """
    g = get_graph()

    def _no_path(reason: str, **extra: Any) -> dict[str, Any]:
        return {
            "start_service": start_service,
            "target_function": target_function,
            "target_file_path": target_file_path,
            "path_trace": [], "hop_count": None,
            "cve_id": cve_id,
            "error": reason,
            **extra,
        }

    if not cve_id and not target_file_path:
        files = _function_files(g, target_function)
        if not files:
            return _no_path(f"Function '{target_function}' not found in the graph.")
        if len(files) > 1:
            return _no_path(
                _ambiguous_error(target_function, files),
                candidates=[_qualified(p, target_function) for p in files],
            )
        target_file_path = files[0]

    if cve_id:
        # Derive the exact affected Function node from the CVE's AFFECTS edge,
        # the same relationship get_blast_radius already uses. This is the
        # recommended way to call the tool for a CVE-driven question: it
        # guarantees the path ends at the precise instance the vulnerability
        # touches (e.g. token-service.validate_token, not auth-service
        # .validate_token).
        cypher = """
        MATCH (c:CVE {id: $cve_id})-[:AFFECTS]->(f:Function)<-[:DEFINES]-(file:File)
        MATCH (s:Service {name: $start_service, is_public: true})
        WITH s, f, file, shortestPath((s)-[:CONTAINS|DEFINES|DEPENDS_ON*1..10]->(f)) AS p
        RETURN
            [n IN nodes(p) | labels(n)[0] + ':' + coalesce(n.name, n.path, n.id)] AS path_trace,
            length(p) AS hop_count,
            file.path AS file_path
        ORDER BY hop_count ASC, path_trace ASC
        LIMIT 1
        """
        result = g.query(cypher, params={
            "start_service": start_service,
            "cve_id": cve_id,
        })
    else:
        cypher = """
        MATCH (s:Service {name: $start_service, is_public: true})
        MATCH (file:File {path: $target_file_path})-[:DEFINES]->(f:Function {name: $target_function})
        WITH s, f, file, shortestPath((s)-[:CONTAINS|DEFINES|DEPENDS_ON*1..10]->(f)) AS p
        RETURN
            [n IN nodes(p) | labels(n)[0] + ':' + coalesce(n.name, n.path, n.id)] AS path_trace,
            length(p) AS hop_count,
            file.path AS file_path
        ORDER BY hop_count ASC, path_trace ASC
        LIMIT 1
        """
        result = g.query(cypher, params={
            "start_service": start_service,
            "target_function": target_function,
            "target_file_path": target_file_path,
        })
    rs = result.result_set
    if not rs:
        return _no_path(
            f"No public path from '{start_service}' to '"
            f"{target_function}'. Either the start service isn't "
            f"public, the function doesn't exist, or there's no "
            f"CONTAINS/DEFINES/DEPENDS_ON path between them."
        )

    row = rs[0]
    raw_trace = row[0]
    if raw_trace is None:
        return {**_no_path("shortestPath returned no nodes."), "hop_count": 0}
    path_trace = [str(item) for item in raw_trace if item]
    # When the query was scoped by CVE, report the Function that the graph
    # actually resolved to (the last node in path_trace) instead of echoing
    # back whatever target_function the caller passed in. That keeps
    # attack_path.target_function consistent with path_trace, e.g. when a
    # different CVE affects get_user_profile rather than validate_token.
    if cve_id and path_trace:
        last_node = path_trace[-1]
        if last_node.startswith("Function:"):
            target_function = last_node[len("Function:"):]
    return {
        "start_service": start_service,
        "target_function": target_function,
        "target_file_path": str(row[2]) if row[2] else target_file_path,
        "path_trace": path_trace,
        "hop_count": int(row[1]) if row[1] is not None else len(path_trace),
        "cve_id": cve_id,
    }


def find_code_owner(
    function_name: str,
    *,
    file_path: str | None = None,
    cve_id: str | None = None,
) -> dict[str, Any]:
    """Find the developer who authored the vulnerable code, for alerting.

    The Function is resolved exactly: through the CVE's AFFECTS edge when
    `cve_id` is given, by (file_path, function_name) when `file_path` is
    given, and otherwise by name only when that name is defined in exactly
    one file. Every matching row is returned and checked, so an ambiguous
    name is reported instead of answered with an arbitrary LIMIT 1 pick.

    Cypher (name-scoped form):
        MATCH (file:File)-[:DEFINES]->(f:Function {name: $function_name})
        OPTIONAL MATCH (file)<-[:AUTHORED]-(dev:Developer)
        OPTIONAL MATCH (dev)-[:OWNS]->(s:Service)
        RETURN file.path, f.name, dev.name, dev.email, dev.slack_handle,
               collect(DISTINCT s.name)
        ORDER BY file_path, function_name, developer_name
    """
    g = get_graph()

    if cve_id:
        match = "MATCH (:CVE {id: $cve_id})-[:AFFECTS]->(f:Function)<-[:DEFINES]-(file:File)"
    elif file_path:
        match = "MATCH (file:File {path: $file_path})-[:DEFINES]->(f:Function {name: $function_name})"
    else:
        match = "MATCH (file:File)-[:DEFINES]->(f:Function {name: $function_name})"

    cypher = match + """
    OPTIONAL MATCH (file)<-[:AUTHORED]-(dev:Developer)
    OPTIONAL MATCH (dev)-[:OWNS]->(s:Service)
    RETURN
        file.path AS file_path,
        f.name AS function_name,
        dev.name AS developer_name,
        dev.email AS email,
        dev.slack_handle AS slack,
        collect(DISTINCT s.name) AS owned_services
    ORDER BY file_path, function_name, developer_name
    """
    result = g.query(cypher, params={
        "function_name": function_name,
        "file_path": file_path,
        "cve_id": cve_id,
    })
    rs = result.result_set

    def _missing(reason: str, **extra: Any) -> dict[str, Any]:
        return {
            "function_name": function_name, "file_path": file_path,
            "developer_name": None, "email": None, "slack": None,
            "owned_services": [], "owners": [],
            "error": reason,
            **extra,
        }

    if not rs:
        return _missing(f"No owner found for function '{function_name}'.")

    targets = sorted({(str(r[0]), str(r[1])) for r in rs})
    if len(targets) > 1:
        names = sorted({name for _, name in targets})
        label = names[0] if len(names) == 1 else function_name
        return _missing(
            _ambiguous_error(label, [path for path, _ in targets]),
            candidates=[_qualified(path, name) for path, name in targets],
        )

    resolved_path, resolved_name = targets[0]
    owners = [
        {
            "developer_name": str(r[2]),
            "email": str(r[3]) if r[3] else None,
            "slack": str(r[4]) if r[4] else None,
            # Sorted for the same reason as the blast-radius lists above.
            "owned_services": sorted(str(x) for x in (r[5] or []) if x),
        }
        for r in rs if r[2]
    ]
    if not owners:
        return {
            **_missing(f"No owner found for function '{resolved_name}' "
                       f"in {resolved_path}."),
            "function_name": resolved_name, "file_path": resolved_path,
        }

    return {
        "function_name": resolved_name,
        "file_path": resolved_path,
        **owners[0],
        "owners": owners,
    }


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------
#
# One entry per tool. The LiteLLM schemas, the keyword classifier, answer
# synthesis, the /tools endpoint and the MCP server all read TOOL_REGISTRY, so
# adding a tool is a single new entry here.

@dataclass
class QuestionContext:
    """What the keyword classifier extracted from a question."""

    question: str
    cve_id: str | None
    function_name: str | None
    service_name: str | None

    def mentions(self, keywords: tuple[str, ...]) -> bool:
        q = self.question.lower()
        return any(k in q for k in keywords)

    @cached_property
    def target_function(self) -> str | None:
        """The function the question names, else the one its CVE affects.

        Lazy, so questions that never need a target don't pay a graph
        round-trip for it.
        """
        if self.function_name:
            return self.function_name
        if self.cve_id:
            return _function_for_cve(self.cve_id)
        return None


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


def _call_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    """Run a registered tool, turning any failure into an error result."""
    tool = TOOL_REGISTRY.get(name)
    if tool is None:
        return {"error": f"Unknown tool: {name}"}
    try:
        return tool.func(**args)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"Tool '{name}' raised: {exc}"}


# ---------------------------------------------------------------------------
# Agent loop
# ---------------------------------------------------------------------------

def _extract_cve_id(text: str) -> str | None:
    m = re.search(r"CVE-\d{4}-\d{4,}", text, re.IGNORECASE)
    return m.group(0).upper() if m else None


# Used only when the graph cannot be reached; the live names are read from
# FalkorDB so questions about *any* function or service in the graph work,
# not just the few that happened to be hardcoded here.
_STATIC_FUNCTIONS = [
    "validate_token", "get_user_profile", "process_payment",
    "handle_request", "issue_token", "send_email",
    "submit_login", "render_login",
]
_STATIC_SERVICES = ["api-gateway", "web-frontend", "auth-service"]

_ENTITY_CACHE: dict[tuple[str, str], tuple[float, list[str]]] = {}
_ENTITY_TTL_S = 60.0


def _graph_names(label: str, prop: str = "name") -> list[str]:
    """All distinct values of a node property for a label, cached briefly.

    Values are returned exactly as stored. They used to be lowercased, which
    meant a name like Repo.get_user came back as repo.get_user and then
    matched nothing when handed to a tool.

    Returns an empty list on any DB failure so callers can fall back to the
    static lists (offline demos, unit tests without a graph).
    """
    now = time.monotonic()
    key = (label, prop)
    cached = _ENTITY_CACHE.get(key)
    if cached and now - cached[0] < _ENTITY_TTL_S:
        return cached[1]
    try:
        rows = get_graph().query(f"MATCH (n:{label}) RETURN DISTINCT n.{prop}").result_set
        names = sorted({str(r[0]) for r in rows if r and r[0]})
    except Exception:  # noqa: BLE001 - degrade to the static candidate lists
        names = []
    _ENTITY_CACHE[key] = (now, names)
    return names


# Identifier-shaped words: snake_case functions, dotted qualified names and
# hyphenated service names.
_TOKEN_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.\-]*")


def _first_named(text: str, candidates: list[str]) -> str | None:
    """The first word of `text` that exactly equals one of `candidates`.

    Words are compared whole and case-sensitively, so 'token' never matches
    inside 'refresh_token' and 'validate_token_v2' is not 'validate_token'.
    """
    known = set(candidates)
    for word in _TOKEN_RE.findall(text):
        word = word.rstrip(".-")
        if word in known:
            return word
    return None


def _extract_function_name(question: str) -> str | None:
    return _first_named(question, _graph_names("Function") or _STATIC_FUNCTIONS)


def _extract_public_service(question: str) -> str | None:
    return _first_named(question, _graph_names("Service") or _STATIC_SERVICES)


def _function_for_cve(cve_id: str) -> str | None:
    """Name of the Function a CVE affects.

    Lets questions that name only the CVE ("who owns the vulnerable function
    in CVE-2026-4421?") reach a tool at all. The tool call itself is scoped by
    cve_id, so this name is only a label and never used to look the function up.
    """
    try:
        rows = get_graph().query(
            "MATCH (c:CVE {id: $cve_id})-[:AFFECTS]->(f:Function) "
            "RETURN f.name AS name ORDER BY name LIMIT 1",
            params={"cve_id": cve_id},
        ).result_set
    except Exception:  # noqa: BLE001 - no CVE context is better than a crash
        return None
    return str(rows[0][0]) if rows and rows[0] and rows[0][0] else None


_GREETINGS = {"hello", "hi", "hey", "yo", "hola", "namaste", "greetings"}
_THANKS = ("thanks", "thank you", "thx", "appreciate")
_FAREWELLS = ("bye", "goodbye", "see you", "cya", "good night")
_HOW_ARE_YOU = ("how are you", "how's it going", "how are things", "how do you feel")
_IDENTITY = (
    "who are you", "what are you", "what can you do", "what do you do",
    "what can i ask", "capabilities",
)


def _conversational_reply(question: str) -> str | None:
    """Friendly reply for small talk, so the chat stays conversational even
    when no LLM is reachable. Returns None for non-small-talk messages."""
    q = re.sub(r"\s+", " ", question.lower()).strip()
    if not q:
        return None
    words = re.sub(r"[^a-z0-9' ]+", " ", q).split()

    if any(p in q for p in _IDENTITY) or q in {"help", "?"}:
        return (
            "I'm GitTrace, a CVE blast-radius agent over FalkorDB. I can answer "
            "three kinds of questions:\n"
            "- Blast radius: \"What's the blast radius of CVE-2026-4421?\"\n"
            "- Attack path: \"What's the shortest path from api-gateway to validate_token?\"\n"
            "- Code owner: \"Who owns validate_token?\""
        )
    if any(p in q for p in _HOW_ARE_YOU):
        return (
            "Doing well, thanks for asking. The graph is loaded and ready. "
            "Ask me about a CVE, an attack path, or who owns a function."
        )
    if any(p in q for p in _THANKS):
        return "Anytime. Throw another CVE or function name at me whenever you're ready."
    if any(p in q for p in _FAREWELLS):
        return "See you. Ping me when the next CVE lands."
    if (words and words[0] in _GREETINGS) or q.startswith(
        ("good morning", "good afternoon", "good evening")
    ):
        return (
            "Hey, GitTrace here, ready to dig into your dependency graph. "
            "Try \"What's the blast radius of CVE-2026-4421?\", "
            "\"What's the shortest path from api-gateway to validate_token?\", "
            "or \"Who owns validate_token?\""
        )
    return None


def _synthesize_answer(question: str, tool_calls: list[ToolCall],
                       tool_results: list[dict[str, Any]],
                       cve_id: str | None) -> str:
    """Turn tool results into a readable answer."""
    if not tool_calls:
        return (
            "I couldn't identify a specific tool to call from that question. "
            "Try asking something like:\n"
            "- 'What's the blast radius of CVE-2026-4421?'\n"
            "- 'What's the shortest path from api-gateway to validate_token?'\n"
            "- 'Who owns validate_token?'"
        )

    parts: list[str] = []
    for call, res in zip(tool_calls, tool_results):
        data = res["result"]
        tool = TOOL_REGISTRY.get(call.name)
        label = tool.label if tool else call.name
        if data.get("error"):
            parts.append(f"[{label}] {data['error']}")
        elif tool:
            parts.append(f"[{label}] {tool.summarize(data)}")

    answer = " ".join(parts)
    if cve_id and "blast radius" in answer.lower():
        answer = f"Re: {cve_id}. " + answer
    return answer


def _pack_tool_results(tool_calls: list[ToolCall],
                       tool_results: list[dict[str, Any]]) -> list[ToolResult]:
    """Pair each executed tool call with its result for the API response."""
    packed: list[ToolResult] = []
    for call, res in zip(tool_calls, tool_results):
        packed.append(ToolResult(
            name=call.name,
            arguments=call.arguments,
            result=res.get("result", {}),
        ))
    return packed


def run_agent(question: str) -> AgentResponse:
    """Keyword-classifier agent: pick tools from the question, execute,
    synthesize. Works without any LLM API key."""
    cve_id = _extract_cve_id(question)
    ctx = QuestionContext(
        question=question,
        cve_id=cve_id,
        function_name=_extract_function_name(question),
        service_name=_extract_public_service(question),
    )

    tool_results: list[dict[str, Any]] = []
    tool_calls: list[ToolCall] = []

    # Registry order is dispatch order: blast radius, then path, then owner.
    for name, tool in TOOL_REGISTRY.items():
        args = tool.plan(ctx)
        if args is None:
            continue
        tool_calls.append(ToolCall(name=name, arguments=args))
        tool_results.append({"name": name, "result": _call_tool(name, args)})

    answer = _synthesize_answer(question, tool_calls, tool_results, cve_id)
    if not tool_calls:
        small_talk = _conversational_reply(question)
        if small_talk:
            answer = small_talk
    return AgentResponse(
        answer=answer,
        tool_calls=tool_calls,
        tool_results=_pack_tool_results(tool_calls, tool_results),
        cve_id=cve_id,
    )


# When the LLM rejects our credentials, every subsequent message would pay
# another failed round-trip before falling back. Remember the failure briefly
# so the chat stays snappy, and retry automatically once the window expires
# (e.g. after the operator fixes the key).
_LLM_AUTH_COOLDOWN_S = 120.0
_llm_auth_cooldown_until = 0.0


def _is_auth_error(exc: BaseException) -> bool:
    return "authentic" in type(exc).__name__.lower()


def _llm_auth_cooldown_active() -> bool:
    return time.monotonic() < _llm_auth_cooldown_until


def _trip_llm_auth_cooldown() -> None:
    global _llm_auth_cooldown_until
    _llm_auth_cooldown_until = time.monotonic() + _LLM_AUTH_COOLDOWN_S


def run_agent_with_litellm(question: str, model: str) -> AgentResponse:
    """Use LiteLLM function calling when the model supports it. Falls back
    to run_agent (keyword classifier) on any failure."""
    if _llm_auth_cooldown_active():
        return run_agent(question)

    try:
        import litellm
    except ImportError:
        return run_agent(question)

    # Determinism comes from the system instruction, not from sampling
    # parameters: Gemini 3+/Flash deprecate temperature/top_p/top_k, so none
    # of them are sent here.
    messages = [
        {
            "role": "system",
            "content": (
                "You are a deterministic security triage agent. Always select "
                "the appropriate tool for the question and never invent data."
            ),
        },
        {"role": "user", "content": question},
    ]
    try:
        response = litellm.completion(
            model=model,
            messages=messages,
            tools=tool_schemas(),
            tool_choice="auto",
            timeout=30.0,
        )
    except Exception as exc:  # noqa: BLE001
        import sys as _sys
        if _is_auth_error(exc):
            _trip_llm_auth_cooldown()
        print(f"[agent] first-turn LLM failed: {type(exc).__name__}: {exc}", file=_sys.stderr, flush=True)
        return run_agent(question)

    choices = getattr(response, "choices", None)
    if not choices:
        return run_agent(question)

    message = choices[0].message
    tool_calls_raw = getattr(message, "tool_calls", None) or []
    if not tool_calls_raw:
        content = getattr(message, "content", "") or ""
        return AgentResponse(answer=content, tool_calls=[],
                             cve_id=_extract_cve_id(question))

    tool_results: list[dict[str, Any]] = []
    tool_calls: list[ToolCall] = []
    for tc in tool_calls_raw:
        name = getattr(tc.function, "name", "")
        args_raw = getattr(tc.function, "arguments", "{}")
        try:
            args = json.loads(args_raw) if isinstance(args_raw, str) else args_raw
        except (json.JSONDecodeError, TypeError):
            args = None
            arg_error = "arguments were not valid JSON"
        else:
            arg_error = f"arguments must be a JSON object, got {type(args).__name__}"
        # The model can send any JSON (a list, a string, null). Report it as a
        # failed call rather than letting ToolCall validation or **args crash
        # the whole request.
        if not isinstance(args, dict):
            tool_calls.append(ToolCall(name=name, arguments={}))
            tool_results.append({"name": name, "result": {
                "error": f"Tool '{name}' was not called: {arg_error}.",
            }})
            continue

        # If the LLM dispatched a CVE-scoped tool without cve_id but the
        # question carries a CVE, scope the call to the affected instance
        # ourselves. This keeps the live backend consistent with the
        # keyword-only agent even when Gemini plays by its own rules.
        tool = TOOL_REGISTRY.get(name)
        if tool is not None and tool.cve_scoped and "cve_id" not in args:
            extracted = _extract_cve_id(question)
            if extracted:
                args["cve_id"] = extracted

        tool_calls.append(ToolCall(name=name, arguments=args))
        tool_results.append({"name": name, "result": _call_tool(name, args)})

    # Execute a second turn asking Gemini to summarize the tool results
    # as plain text. We deliberately avoid the tool-calling message format
    # on the second turn: when the assistant message contains tool_calls,
    # Gemini tries to call another (often invented) tool instead of
    # answering. Instead we send a fresh user message with the tool results
    # injected as context.
    synthesized = _synthesize_answer(question, tool_calls, tool_results,
                                     _extract_cve_id(question))

    results_summary = "\n".join(
        f"- {r['name']}: {json.dumps(r['result'])}"
        for r in tool_results
    )
    follow_messages = [
        {
            "role": "user",
            "content": (
                f"Question: {question}\n\n"
                f"I ran the following graph database tools and got these "
                f"results:\n{results_summary}\n\n"
                f"Based on these results, give a concise incident-response "
                f"answer to the question."
            ),
        },
    ]
    content = ""
    try:
        # Do NOT pass tools on the second turn: without them Gemini is
        # forced to produce a text answer instead of another tool call.
        final = litellm.completion(
            model=model,
            messages=follow_messages,
            max_tokens=1024,
            timeout=30.0,
        )
        content = (final.choices[0].message.content or "").strip()
        import sys as _sys
        print(f"[agent] second-turn content len={len(content)} preview={content[:120]!r}", file=_sys.stderr, flush=True)
        if content and len(content) > 40:
            return AgentResponse(answer=content, tool_calls=tool_calls,
                                 tool_results=_pack_tool_results(tool_calls, tool_results),
                                 cve_id=_extract_cve_id(question))
    except Exception as exc:  # noqa: BLE001
        import sys as _sys
        if _is_auth_error(exc):
            _trip_llm_auth_cooldown()
        print(f"[agent] second-turn LLM failed: {type(exc).__name__}: {exc}", file=_sys.stderr, flush=True)

    # Return the LLM answer if we got meaningful content; otherwise fall back to synthesized
    if content and len(content) > 40:
        return AgentResponse(answer=content, tool_calls=tool_calls,
                             tool_results=_pack_tool_results(tool_calls, tool_results),
                             cve_id=_extract_cve_id(question))

    return AgentResponse(
        answer=synthesized,
        tool_calls=tool_calls,
        tool_results=_pack_tool_results(tool_calls, tool_results),
        cve_id=_extract_cve_id(question),
    )


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="GitTrace",
    description="CVE blast-radius agent over FalkorDB.",
    version="0.1.0",
)

# Restrict CORS to the frontend origins that are allowed to call the API.
# Local dev uses localhost:5500 + localhost:8000; the deployed frontend origin
# is read from GITTRACE_FRONTEND_ORIGIN (defaults to localhost:5500 if unset) so
# the live deployment isn't blocked by the current localhost-only allowlist.
_deployed_origin = os.environ.get("GITTRACE_FRONTEND_ORIGIN", "http://localhost:5500")
_allowed_origins: list[str] = []
for name in (_deployed_origin, "http://localhost:5500", "http://localhost:8000"):
    if name and name not in _allowed_origins:
        _allowed_origins.append(name)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["Content-Type"],
    max_age=600,
)


@app.get("/")
def root() -> dict[str, str]:
    """Root liveness probe so browser pings and platform health checks
    don't land on a 404."""
    return {"status": "ok", "app": "GitTrace"}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/query", response_model=AgentResponse)
def query(req: QueryRequest) -> AgentResponse:
    if not req.question or not req.question.strip():
        raise HTTPException(
            status_code=400,
            detail="question is required and cannot be empty or whitespace-only",
        )

    model = req.model or os.environ.get("LITELLM_MODEL", "gemini/gemini-flash-lite-latest")
    try:
        return run_agent_with_litellm(req.question, model)
    except Exception:  # noqa: BLE001
        return run_agent(req.question)


@app.get("/tools")
def list_tools() -> dict[str, list[dict[str, Any]]]:
    return {"tools": tool_schemas()}


@app.get("/demo")
def demo_scenario() -> dict[str, Any]:
    """Run the scripted demo scenario from SPEC.md §4 and return results."""
    blast = get_blast_radius("CVE-2026-4421")
    # CVE-2026-4421 specifically affects token-service.validate_token, so scope
    # the attack-path tool to that instance via the CVE's AFFECTS edge.
    path = find_shortest_dependency_path(
        "api-gateway", "validate_token", cve_id="CVE-2026-4421"
    )
    owner = find_code_owner("validate_token", cve_id="CVE-2026-4421")
    return {
        "blast_radius": blast,
        "attack_path": path,
        "code_owner": owner,
    }


def main() -> None:
    import uvicorn
    port = int(os.environ.get("GITTRACE_PORT", "8000"))
    print(f"GitTrace API starting on :{port}")
    print(f"  POST /query  — ask a security question")
    print(f"  GET  /tools  — list available graph tools")
    print(f"  GET  /demo   — run the scripted demo scenario")
    uvicorn.run(app, host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
