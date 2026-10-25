"""
app.py — FastAPI routes over gittrace.core.

The graph tools, the tool registry and the agent live in gittrace.core; this
module only exposes them over HTTP.
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from gittrace.core.agent import run_agent, run_agent_with_litellm
from gittrace.core.models import AgentResponse
from gittrace.core.registry import tool_schemas
from gittrace.core.tools import (
    find_code_owner,
    find_shortest_dependency_path,
    get_blast_radius,
)


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
