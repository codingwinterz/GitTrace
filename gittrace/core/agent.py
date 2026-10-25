"""
gittrace.core.agent — answer a security question with the graph tools.

Two paths, same tools:
  - run_agent_with_litellm: the model picks tools by function calling and
    writes the answer. Falls back to run_agent on any LLM failure.
  - run_agent: a keyword classifier picks tools; no API key needed.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from typing import Any

from gittrace.core.models import AgentResponse, ToolCall, ToolResult
from gittrace.core.question import QuestionContext, extract_cve_id
from gittrace.core.registry import TOOL_REGISTRY, call_tool, tool_schemas

# LiteLLM reads GEMINI_API_KEY automatically for gemini/* models; copy from our
# env name. .env has been loaded by gittrace.graph.connection at this point.
if os.environ.get("Gemini_API_Key") and not os.environ.get("GEMINI_API_KEY"):
    os.environ["GEMINI_API_KEY"] = os.environ["Gemini_API_Key"]


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
    """Pair each executed tool call with its result for the response."""
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
    ctx = QuestionContext.from_question(question)

    tool_results: list[dict[str, Any]] = []
    tool_calls: list[ToolCall] = []

    # Registry order is dispatch order: blast radius, then path, then owner.
    for name, tool in TOOL_REGISTRY.items():
        args = tool.plan(ctx)
        if args is None:
            continue
        tool_calls.append(ToolCall(name=name, arguments=args))
        tool_results.append({"name": name, "result": call_tool(name, args)})

    answer = _synthesize_answer(question, tool_calls, tool_results, ctx.cve_id)
    if not tool_calls:
        small_talk = _conversational_reply(question)
        if small_talk:
            answer = small_talk
    return AgentResponse(
        answer=answer,
        tool_calls=tool_calls,
        tool_results=_pack_tool_results(tool_calls, tool_results),
        cve_id=ctx.cve_id,
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
        if _is_auth_error(exc):
            _trip_llm_auth_cooldown()
        print(f"[agent] first-turn LLM failed: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        return run_agent(question)

    choices = getattr(response, "choices", None)
    if not choices:
        return run_agent(question)

    message = choices[0].message
    tool_calls_raw = getattr(message, "tool_calls", None) or []
    if not tool_calls_raw:
        content = getattr(message, "content", "") or ""
        return AgentResponse(answer=content, tool_calls=[],
                             cve_id=extract_cve_id(question))

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
        # ourselves. This keeps the LLM path consistent with the keyword-only
        # agent even when Gemini plays by its own rules.
        tool = TOOL_REGISTRY.get(name)
        if tool is not None and tool.cve_scoped and "cve_id" not in args:
            extracted = extract_cve_id(question)
            if extracted:
                args["cve_id"] = extracted

        tool_calls.append(ToolCall(name=name, arguments=args))
        tool_results.append({"name": name, "result": call_tool(name, args)})

    # Execute a second turn asking Gemini to summarize the tool results
    # as plain text. We deliberately avoid the tool-calling message format
    # on the second turn: when the assistant message contains tool_calls,
    # Gemini tries to call another (often invented) tool instead of
    # answering. Instead we send a fresh user message with the tool results
    # injected as context.
    synthesized = _synthesize_answer(question, tool_calls, tool_results,
                                     extract_cve_id(question))

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
        print(f"[agent] second-turn content len={len(content)} preview={content[:120]!r}", file=sys.stderr, flush=True)
    except Exception as exc:  # noqa: BLE001
        if _is_auth_error(exc):
            _trip_llm_auth_cooldown()
        print(f"[agent] second-turn LLM failed: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)

    # Return the LLM answer if we got meaningful content; otherwise fall back to synthesized
    if content and len(content) > 40:
        return AgentResponse(answer=content, tool_calls=tool_calls,
                             tool_results=_pack_tool_results(tool_calls, tool_results),
                             cve_id=extract_cve_id(question))

    return AgentResponse(
        answer=synthesized,
        tool_calls=tool_calls,
        tool_results=_pack_tool_results(tool_calls, tool_results),
        cve_id=extract_cve_id(question),
    )
