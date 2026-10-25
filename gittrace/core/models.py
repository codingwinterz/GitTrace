"""gittrace.core.models — the agent's response shapes."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


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
