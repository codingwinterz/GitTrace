"""
gittrace.llm.gateway — the model layer through the Respan Gateway.

$GITTRACE_GATEWAY=1 sends every model call in this process through an
in-process [Respan Gateway](https://github.com/respanai/respan-gateway), the
open-source LLM gateway: one endpoint for every vendor, with the model names,
fallback routes and client keys of a `gateway.toml`. It is off by default;
without it the model layer is LiteLLM calling the provider directly (see
gittrace.llm.client).

    GITTRACE_GATEWAY         1/true/yes/on routes the model layer through the gateway
    GITTRACE_GATEWAY_CONFIG  a `gateway.toml` to read; without it the gateway is
                             configured from the provider keys in the environment
                             (OPENAI_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY,
                             ...) plus local Ollama, the way respan-gateway
                             configures itself with no config file. A
                             `gateway.toml` in the current directory is never
                             read: that directory is usually the project being
                             scanned, and its files must not configure GitTrace.

Model names are the gateway's, not LiteLLM's: `ollama/llama3.1:8b` (GitTrace's
default) is the gateway's `ollama` provider, `claude-haiku-5-5` is routed to
Anthropic by name, and a `[routes.smart]` in `gateway.toml` is asked for as
`--model smart`, with its own fallbacks. Nothing else changes: the same
prompt, temperature, seed, reply-token limit, JSON schema and timeout as the
LiteLLM path, and the same error types (ModelUnavailable, ModelCallFailed).

No socket is opened: the request goes to the gateway inside this process
(`gw.request`), and the gateway spends the developer's own provider keys.
Respan's own tracing is a separate, optional plugin (`[plugins.respan]`) and no
Respan account or credits are needed for any of this.
"""

from __future__ import annotations

import atexit
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from gittrace.llm.client import (
    MAX_REPLY_TOKENS,
    SEED,
    TEMPERATURE,
    ModelCallFailed,
    ModelUnavailable,
)

GATEWAY_ENV = "GITTRACE_GATEWAY"
CONFIG_ENV = "GITTRACE_GATEWAY_CONFIG"
OLLAMA_BASE_ENV = "OLLAMA_API_BASE"
_TRUTHY = frozenset({"1", "true", "yes", "on"})

# The vendors respan-gateway itself takes from the environment, with the keys
# it reads for them. A key stays in the environment: the config only names it
# (`env:NAME`). A vendor not listed here goes in a gateway.toml.
ENV_VENDORS = (
    ("openai", "OPENAI_API_KEY"),
    ("anthropic", "ANTHROPIC_API_KEY"),
    ("gemini", "GEMINI_API_KEY"),
    ("groq", "GROQ_API_KEY"),
    ("deepseek", "DEEPSEEK_API_KEY"),
    ("openrouter", "OPENROUTER_API_KEY"),
    ("xai", "XAI_API_KEY"),
    ("mistral", "MISTRAL_API_KEY"),
    ("together", "TOGETHER_API_KEY"),
    ("fireworks", "FIREWORKS_API_KEY"),
    ("cerebras", "CEREBRAS_API_KEY"),
    ("perplexity", "PERPLEXITY_API_KEY"),
    ("deepinfra", "DEEPINFRA_API_KEY"),
)

_gateway: Any = None          # this process's gateway, opened on first use


def enabled() -> bool:
    """Is the model layer routed through the gateway ($GITTRACE_GATEWAY)?"""
    return os.environ.get(GATEWAY_ENV, "").strip().lower() in _TRUTHY


def complete(model: str, messages: list[dict], schema: type[BaseModel], *, timeout: float) -> str:
    """One chat reply's text, through the gateway. The caller validates it, as
    it does for the LiteLLM path, so a reply that ignores the JSON schema is
    retried there. Raises ModelUnavailable / ModelCallFailed."""
    gateway = _open()
    respan_gateway, httpx = _import()
    body = {
        "model": model,
        "messages": messages,
        "temperature": TEMPERATURE,
        "seed": SEED,
        "max_tokens": MAX_REPLY_TOKENS,
        "response_format": {"type": "json_schema", "json_schema": {
            "name": schema.__name__, "schema": schema.model_json_schema(), "strict": True}},
    }
    try:
        response = gateway.request("POST", "/v1/chat/completions", json=body, timeout=timeout)
    except httpx.ReadTimeout as exc:
        raise ModelCallFailed(f"{model} did not answer within {timeout:g} s "
                              f"(set $GITTRACE_LLM_TIMEOUT to wait longer)") from exc
    except respan_gateway.GatewayError as exc:
        raise ModelUnavailable(f"cannot call {model} through the gateway: {_first_line(exc)}") from exc
    if response.status_code >= 400:
        failed = ModelCallFailed if response.status_code >= 500 else ModelUnavailable
        raise failed(f"{model} through the gateway: {response.status_code} {_error_text(response)}")
    try:
        content = response.json()["choices"][0]["message"]["content"]
    except (AttributeError, KeyError, IndexError, TypeError, ValueError) as exc:
        raise ModelCallFailed(f"{model} through the gateway returned a response with no message") from exc
    return content or ""


# The install command, as the README gives it (the extra is not in v2.0.0).
INSTALL = 'pipx install --force "gittrace[gateway] @ git+https://github.com/codingwinterz/GitTrace"'


def _import():
    """respan_gateway (and the httpx it brings), or ModelUnavailable: the wheel
    covers a limited set of platforms, so GitTrace reports it and the LiteLLM
    path stays available."""
    try:
        import httpx
        import respan_gateway
    except ImportError as exc:
        raise ModelUnavailable(
            f"${GATEWAY_ENV} is set but respan-gateway is not installed "
            f"(install GitTrace with the gateway extra: {INSTALL}; "
            f"or unset ${GATEWAY_ENV} to use LiteLLM)"
        ) from exc
    return respan_gateway, httpx


def _open():
    """This process's gateway, built on first use and kept for the run."""
    global _gateway
    if _gateway is None:
        respan_gateway, _ = _import()
        source = _config()
        try:
            built = (respan_gateway.Gateway.from_file(source) if isinstance(source, Path)
                     else respan_gateway.Gateway(source))
        except (respan_gateway.ConfigError, OSError) as exc:
            raise ModelUnavailable(
                f"the gateway's configuration could not be read: {_first_line(exc)}. "
                f"${CONFIG_ENV} names a gateway.toml; without it the provider keys in the "
                f"environment are used."
            ) from exc
        except respan_gateway.GatewayError as exc:
            raise ModelUnavailable(f"the gateway could not be started: {_first_line(exc)}") from exc
        atexit.register(_close)
        _gateway = built
    return _gateway


def _close() -> None:
    global _gateway
    gateway, _gateway = _gateway, None
    if gateway is not None:
        gateway.close()


def _reset() -> None:
    """Forget the process's gateway (tests: each one brings its own config)."""
    _close()


def _config() -> str | Path:
    """The `gateway.toml` $GITTRACE_GATEWAY_CONFIG names, else a config built from
    the provider keys in the environment (see the module docstring)."""
    named = os.environ.get(CONFIG_ENV, "").strip()
    if named:
        return Path(named).expanduser()
    lines = [f"# Built by GitTrace from the environment (${CONFIG_ENV} names a file).", "ui = false"]
    for vendor, var in ENV_VENDORS:
        if os.environ.get(var, "").strip():
            lines += ["", f"[providers.{vendor}]", f'vendor = "{vendor}"', f'key = "env:{var}"']
    lines += ["", "[providers.ollama]", 'vendor = "ollama"']     # GitTrace's own default models
    base = os.environ.get(OLLAMA_BASE_ENV, "").strip()
    if base:
        lines.append(f'base_url = "{base}"')
    return "\n".join(lines) + "\n"


def _error_text(response: Any) -> str:
    """The gateway's (or its provider's) message from an error response."""
    try:
        error = response.json().get("error")
    except (AttributeError, TypeError, ValueError):
        error = None
    if isinstance(error, Mapping):
        error = error.get("message")
    if isinstance(error, str) and error.strip():
        return _first_line(error)
    return _first_line(getattr(response, "text", "") or "")


def _first_line(exc: object) -> str:
    text = str(exc).strip()
    return text.splitlines()[0][:300] if text else "no detail"
