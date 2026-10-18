"""
app.py — GitTrace Phase 3

FastAPI backend + LLM agent loop. The agent receives a natural-language
security question (e.g. a CVE alert) and calls one or more of the three
FalkorDB graph tools:

  - get_blast_radius(cve_id)
  - find_shortest_dependency_path(start_service, target_function,
                                  *, target_file_path=None, cve_id=None)
  - find_code_owner(function_name)

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
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

load_dotenv(Path(__file__).resolve().parent / ".env")

# LiteLLM reads GEMINI_API_KEY automatically for gemini/* models; copy from our env name.
if os.environ.get("Gemini_API_Key") and not os.environ.get("GEMINI_API_KEY"):
    os.environ["GEMINI_API_KEY"] = os.environ["Gemini_API_Key"]

from utils import get_db, get_graph  # noqa: E402


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
# Graph tools (the three FalkorDB-backed capabilities from SPEC.md)
# ---------------------------------------------------------------------------

def get_blast_radius(cve_id: str) -> dict[str, Any]:
    """Find all services and functions impacted by a CVE, showing the
    propagation path.

    Cypher (from SPEC.md):
        MATCH path = (c:CVE {id: $cve_id})-[:AFFECTS]->(f:Function)
        OPTIONAL MATCH affected = (f)-[:CALLS*1..5]->(downstream:Function)
        OPTIONAL MATCH downstream_service = (downstream)<-[:DEFINES]-(f2:File)<-[:CONTAINS]-(s:Service)
        RETURN c.id, c.severity,
               collect(DISTINCT s.name),
               collect(DISTINCT downstream.name),
               count(DISTINCT s)
    """
    g = get_graph(None, "gittrace")

    cypher = """
    MATCH path = (c:CVE {id: $cve_id})-[:AFFECTS]->(f:Function)
    OPTIONAL MATCH affected = (f)-[:CALLS*1..5]->(downstream:Function)
    OPTIONAL MATCH downstream_service = (downstream)<-[:DEFINES]-(f2:File)<-[:CONTAINS]-(s:Service)
    RETURN
        c.id AS cve_id,
        c.severity AS severity,
        collect(DISTINCT s.name) AS impacted_services,
        collect(DISTINCT downstream.name) AS impacted_functions,
        count(DISTINCT s) AS service_count
    """
    result = g.query(cypher, params={"cve_id": cve_id})
    rs = result.result_set
    if not rs:
        return {
            "cve_id": cve_id, "severity": None,
            "impacted_services": [], "impacted_functions": [],
            "service_count": 0,
            "error": f"CVE '{cve_id}' not found in the graph.",
        }

    row = rs[0]
    return {
        "cve_id": str(row[0]) if row[0] else cve_id,
        "severity": str(row[1]) if row[1] else None,
        # collect() returns rows in graph-traversal order, which FalkorDB does
        # not guarantee to be stable. Sort so the contract is deterministic.
        "impacted_services": sorted(str(x) for x in (row[2] or []) if x),
        "impacted_functions": sorted(str(x) for x in (row[3] or []) if x),
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
    sharing its name. If `target_file_path` is supplied, the query matches
    the exact Function node defined by that file. If `cve_id` is supplied,
    the tool derives the exact affected Function node from the CVE's AFFECTS
    edge — the same source get_blast_radius already uses — so the attack-path
    and blast-radius tools are guaranteed to point at the same vulnerable
    code.

    When neither is provided the tool falls back to a name-only match (the
    previous behaviour). That is still correct for functions that only exist
    in one place, but it is a *known limitation* for duplicated names like
    validate_token, where the name alone doesn't say which instance the CVE
    affects. See README §Known limitations.

    Implementation note: FalkorDB only supports shortestPath in WITH or
    RETURN clauses, so the Cypher uses WITH ... shortestPath ... AS p.
    The path must traverse CONTAINS (Service->File), DEFINES (File->
    Function), DEPENDS_ON (Service->Service) because a Function lives
    inside a File inside a Service, and services depend on other services.
    """
    g = get_graph(None, "gittrace")

    if cve_id:
        # Derive the exact affected Function node from the CVE's AFFECTS edge,
        # the same relationship get_blast_radius already uses. This is the
        # recommended way to call the tool for a CVE-driven question: it
        # guarantees the path ends at the precise instance the vulnerability
        # touches (e.g. token-service.validate_token, not auth-service
        # .validate_token), and it stays correct if another service later
        # defines a function with the same name.
        cypher = """
        MATCH (c:CVE {id: $cve_id})-[:AFFECTS]->(f:Function)
        MATCH (s:Service {name: $start_service, is_public: true})
        WITH s, f, shortestPath((s)-[:CONTAINS|DEFINES|DEPENDS_ON*1..10]->(f)) AS p
        RETURN
            [n IN nodes(p) | labels(n)[0] + ':' + coalesce(n.name, n.path, n.id)] AS path_trace,
            length(p) AS hop_count
        ORDER BY hop_count ASC, path_trace ASC
        LIMIT 1
        """
        result = g.query(cypher, params={
            "start_service": start_service,
            "target_function": target_function,
            "cve_id": cve_id,
        })
    elif target_file_path:
        cypher = """
        MATCH (s:Service {name: $start_service, is_public: true})
        MATCH (f:File {path: $target_file_path})-[:DEFINES]->(f2:Function {name: $target_function})
        WITH s, f2, shortestPath((s)-[:CONTAINS|DEFINES|DEPENDS_ON*1..10]->(f2)) AS p
        RETURN
            [n IN nodes(p) | labels(n)[0] + ':' + coalesce(n.name, n.path, n.id)] AS path_trace,
            length(p) AS hop_count
        ORDER BY hop_count ASC, path_trace ASC
        LIMIT 1
        """
        result = g.query(cypher, params={
            "start_service": start_service,
            "target_function": target_function,
            "target_file_path": target_file_path,
        })
    else:
        cypher = """
        MATCH (s:Service {name: $start_service, is_public: true})
        MATCH (f:Function {name: $target_function})
        WITH s, f, shortestPath((s)-[:CONTAINS|DEFINES|DEPENDS_ON*1..10]->(f)) AS p
        RETURN
            [n IN nodes(p) | labels(n)[0] + ':' + coalesce(n.name, n.path, n.id)] AS path_trace,
            length(p) AS hop_count
        ORDER BY hop_count ASC, path_trace ASC
        LIMIT 1
        """
        result = g.query(cypher, params={
            "start_service": start_service,
            "target_function": target_function,
        })
    rs = result.result_set
    if not rs:
        reason = (
            f"No public path from '{start_service}' to '"
            f"{target_function}'. Either the start service isn't "
            f"public, the function doesn't exist, or there's no "
            f"CONTAINS/DEFINES/DEPENDS_ON path between them."
        )
        return {
            "start_service": start_service,
            "target_function": target_function,
            "path_trace": [], "hop_count": None,
            "cve_id": cve_id,
            "error": reason,
        }

    row = rs[0]
    raw_trace = row[0]
    if raw_trace is None:
        return {
            "start_service": start_service,
            "target_function": target_function,
            "path_trace": [], "hop_count": 0,
            "cve_id": cve_id,
            "error": "shortestPath returned no nodes.",
        }
    path_trace = [str(item) for item in raw_trace if item]
    # When the query was scoped by CVE, report the Function that the graph
    # actually resolved to (the last node in path_trace) instead of echoing
    # back whatever target_function the caller passed in. That keeps
    # attack_path.target_function consistent with path_trace, e.g. when a
    # different CVE affects get_user_profile rather than validate_token.
    # For name-only and file-scoped queries there's no resolved target above
    # the input, so keep echoing the parameter there.
    if cve_id and path_trace:
        last_node = path_trace[-1]
        if last_node.startswith("Function:"):
            target_function = last_node[len("Function:"):]
    return {
        "start_service": start_service,
        "target_function": target_function,
        "path_trace": path_trace,
        "hop_count": int(row[1]) if row[1] is not None else len(path_trace),
        "cve_id": cve_id,
    }


def find_code_owner(function_name: str) -> dict[str, Any]:
    """Find the developer who owns/authored the vulnerable code for
    alerting.

    Cypher (from SPEC.md):
        MATCH (f:Function {name: $function_name})<-[:DEFINES]-(file:File)<-[:AUTHORED]-(dev:Developer)
        OPTIONAL MATCH (dev)-[:OWNS]->(s:Service)
        RETURN dev.name, dev.email, dev.slack_handle, collect(DISTINCT s.name)
        LIMIT 1
    """
    g = get_graph(None, "gittrace")

    cypher = """
    MATCH (f:Function {name: $function_name})<-[:DEFINES]-(file:File)<-[:AUTHORED]-(dev:Developer)
    OPTIONAL MATCH (dev)-[:OWNS]->(s:Service)
    RETURN
        dev.name AS developer_name,
        dev.email AS email,
        dev.slack_handle AS slack,
        collect(DISTINCT s.name) AS owned_services
    LIMIT 1
    """
    result = g.query(cypher, params={"function_name": function_name})
    rs = result.result_set
    if not rs:
        return {
            "function_name": function_name,
            "developer_name": None, "email": None, "slack": None,
            "owned_services": [],
            "error": f"No owner found for function '{function_name}'.",
        }

    row = rs[0]
    return {
        "function_name": function_name,
        "developer_name": str(row[0]) if row[0] else None,
        "email": str(row[1]) if row[1] else None,
        "slack": str(row[2]) if row[2] else None,
        # Sorted for the same reason as the blast-radius lists above.
        "owned_services": sorted(str(x) for x in (row[3] or []) if x),
    }


TOOL_REGISTRY: dict[str, Any] = {
    "get_blast_radius": get_blast_radius,
    "find_shortest_dependency_path": find_shortest_dependency_path,
    "find_code_owner": find_code_owner,
}


def tool_schemas() -> list[dict[str, Any]]:
    """Return OpenAI-format tool definitions for the three graph tools."""
    return [
        {
            "type": "function",
            "function": {
                "name": "get_blast_radius",
                "description": (
                    "Find all services and functions impacted by a CVE, "
                    "showing the propagation path. Call this when asked "
                    "about blast radius, impact, or what breaks if a "
                    "vulnerable function is taken offline."
                ),
                "parameters": {
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
            },
        },
        {
            "type": "function",
            "function": {
                "name": "find_shortest_dependency_path",
                "description": (
                    "Use FalkorDB's native shortestPath to trace how an attacker "
                    "reaches a specific vulnerable Function node from a public-facing "
                    "service. The target is scoped by the CVE's AFFECTS edge when a "
                    "cve_id is supplied (recommended for CVE-driven questions), or by "
                    "target_file_path when the exact instance is known. Without either, "
                    "the tool falls back to a name-only match for functions that exist "
                    "in a single place only."
                ),
                "parameters": {
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
                        "cve_id": {
                            "type": "string",
                            "description": "Optional. When supplied, the tool derives the exact affected Function node from the CVE's AFFECTS edge, so the attack-path tool points at the same function the blast-radius tool reports. Recommended for CVE-driven questions.",
                        },
                        "target_file_path": {
                            "type": "string",
                            "description": "Optional. When supplied, the tool matches the exact Function node defined by that file path (e.g. '/token-service/token.py'). Use when the file context is known.",
                        },
                    },
                    "required": ["start_service", "target_function"],
                    "additionalProperties": False,
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "find_code_owner",
                "description": (
                    "Find the developer who owns/authored the vulnerable "
                    "code for alerting. Call this when asked who owns the "
                    "code, who to notify, or the contact info for a function."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "function_name": {
                            "type": "string",
                            "description": "Function name, e.g. 'validate_token'.",
                        },
                    },
                    "required": ["function_name"],
                    "additionalProperties": False,
                },
            },
        },
    ]


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

_ENTITY_CACHE: dict[str, tuple[float, list[str]]] = {}
_ENTITY_TTL_S = 60.0


def _graph_names(label: str, prop: str = "name") -> list[str]:
    """All values of a node property for a label, cached briefly.

    Returns an empty list on any DB failure so callers can fall back to the
    static lists (offline demos, unit tests without a graph).
    """
    now = time.monotonic()
    cached = _ENTITY_CACHE.get(label)
    if cached and now - cached[0] < _ENTITY_TTL_S:
        return cached[1]
    try:
        rows = get_graph().query(f"MATCH (n:{label}) RETURN n.{prop}").result_set
        names = sorted({str(r[0]).lower() for r in rows if r and r[0]})
    except Exception:  # noqa: BLE001 - degrade to the static candidate lists
        names = []
    _ENTITY_CACHE[label] = (now, names)
    return names


def _first_named(text: str, candidates: list[str]) -> str | None:
    """Longest candidate appearing in `text` (so 'refresh_token' beats 'token')."""
    for c in sorted(set(candidates), key=len, reverse=True):
        if c and c in text:
            return c
    return None


def _extract_function_name(q: str) -> str | None:
    return _first_named(q, _graph_names("Function") or _STATIC_FUNCTIONS)


def _extract_public_service(q: str) -> str | None:
    return _first_named(q, _graph_names("Service") or _STATIC_SERVICES)


def _function_for_cve(cve_id: str) -> str | None:
    """Resolve the Function a CVE affects.

    Lets questions that name only the CVE ("who owns the vulnerable function
    in CVE-2026-4421?") reach the same target the blast-radius tool reports.
    """
    try:
        rows = get_graph().query(
            "MATCH (c:CVE {id: $cve_id})-[:AFFECTS]->(f:Function) "
            "RETURN f.name LIMIT 1",
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
        name = call.name
        data = res["result"]

        if name == "get_blast_radius":
            sev = data.get("severity") or "unknown"
            services = data.get("impacted_services") or []
            funcs = data.get("impacted_functions") or []
            count = data.get("service_count", 0)
            err = data.get("error")
            if err:
                parts.append(f"[blast radius] {err}")
            else:
                parts.append(
                    f"[blast radius] CVE {data.get('cve_id')} is {sev}. "
                    f"{count} service(s) impacted: "
                    f"{', '.join(services) or 'none'}. "
                    f"Downstream functions: {', '.join(funcs) or 'none'}."
                )

        elif name == "find_shortest_dependency_path":
            err = data.get("error")
            trace = data.get("path_trace") or []
            hops = data.get("hop_count")
            if err:
                parts.append(f"[attack path] {err}")
            else:
                trace_line = " -> ".join(trace)
                parts.append(
                    f"[attack path] From {data.get('start_service')} to "
                    f"{data.get('target_function')}: {trace_line} "
                    f"({hops} hop{'s' if hops != 1 else ''})."
                )

        elif name == "find_code_owner":
            err = data.get("error")
            if err:
                parts.append(f"[code owner] {err}")
            else:
                owner = data.get("developer_name") or "unknown"
                email = data.get("email") or ""
                slack = data.get("slack") or ""
                owned = data.get("owned_services") or []
                contact = f"{owner}"
                if email:
                    contact += f" ({email})"
                if slack:
                    contact += f", {slack}"
                parts.append(
                    f"[code owner] {data.get('function_name')} is owned by "
                    f"{contact}. Also owns: {', '.join(owned) or 'none'}."
                )

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
    q = question.lower()

    wanted: list[str] = []
    target = _extract_function_name(q)
    start = _extract_public_service(q)

    wants_owner = any(
        k in q for k in ("owner", "notify", "contact", "who", "slack", "email")
    )
    wants_path = any(
        k in q for k in ("path", "shortest", "attack", "entry", "reach", "how does")
    )

    # A question can name the CVE but not the function. Resolve the target
    # through the CVE's AFFECTS edge so it still reaches the right tool.
    if target is None and cve_id and (wants_owner or wants_path):
        target = _function_for_cve(cve_id)

    # Blast radius is CVE-driven; other tools fall back to graph defaults.
    if cve_id:
        wanted.append("get_blast_radius")
    if wants_path and target:
        wanted.append("find_shortest_dependency_path")
    if wants_owner and target:
        wanted.append("find_code_owner")

    tool_results: list[dict[str, Any]] = []
    tool_calls: list[ToolCall] = []

    for name in wanted:
        tool = TOOL_REGISTRY[name]
        if name == "get_blast_radius":
            args = {"cve_id": cve_id or "CVE-2026-4421"}
        elif name == "find_shortest_dependency_path":
            # CVE-driven path queries should target the exact affected function
            # instance (via the CVE's AFFECTS edge) so the path ends at the same
            # code the blast-radius tool reports; fall back to name-only when the
            # question has no CVE context.
            if cve_id:
                args = {"start_service": start or "api-gateway",
                        "target_function": target or "validate_token",
                        "cve_id": cve_id}
            else:
                args = {"start_service": start or "api-gateway",
                        "target_function": target or "validate_token"}
        else:
            args = {"function_name": target or "validate_token"}

        try:
            result = tool(**args)
        except Exception as exc:  # noqa: BLE001
            result = {"error": f"Tool '{name}' raised: {exc}"}

        tool_calls.append(ToolCall(name=name, arguments=args))
        tool_results.append({"name": name, "result": result})

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
            args = {}

        # If the LLM dispatched find_shortest_dependency_path without scoping but
        # we already have a CVE context for this question, scope the call at the
        # affected instance ourselves. This keeps the live backend consistent with
        # the keyword-only agent even when Gemini plays by its own rules.
        if name == "find_shortest_dependency_path" and "cve_id" not in args:
            extracted = _extract_cve_id(question)
            if extracted:
                args["cve_id"] = extracted

        tool = TOOL_REGISTRY.get(name)
        if tool is None:
            tool_results.append({"name": name,
                                 "result": {"error": f"Unknown tool: {name}"}})
            tool_calls.append(ToolCall(name=name, arguments=args))
            continue
        try:
            result = tool(**args)
        except Exception as exc:  # noqa: BLE001
            result = {"error": f"Tool '{name}' raised: {exc}"}
        tool_calls.append(ToolCall(name=name, arguments=args))
        tool_results.append({"name": name, "result": result})

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
    owner = find_code_owner("validate_token")
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
