"""
gittrace.llm.client — one structured model call, through LiteLLM.

    model:    --model, else $GITTRACE_MODEL, else ollama/llama3.1:8b
    options:  num_ctx 8192, temperature 0.1, a fixed seed, at most 1024 reply
              tokens, a timeout ($GITTRACE_LLM_TIMEOUT seconds, default 120)
    output:   the task's pydantic schema, also sent as a JSON schema (Ollama
              constrains decoding to it). The reply is validated; an invalid
              one is sent back once with the validation error, and a second
              invalid reply raises InvalidOutput.

`ollama/<name>` goes to Ollama's chat endpoint (LiteLLM's `ollama_chat/`
provider). LiteLLM's plain `ollama/` provider flattens the messages into one
prompt string, which would put the instructions and the untrusted code in the
same turn. The model name the user chose is what reports and the cache show.

Errors are raised, never papered over:
  ModelUnavailable  the model cannot be called at all (Ollama not running,
                    model not pulled, bad credentials): nothing else will work
  ModelCallFailed   this call failed (a timeout, a server error)
  OutOfMemory       a ModelCallFailed: the GPU ran out of memory, and the
                    recovery below did not help
  InvalidOutput     two replies in a row did not match the schema
Each error carries the attempts made and the seconds spent.

Out of GPU memory (Ollama only). llama3.1:8b at num_ctx 8192 takes about
5.6 GiB of VRAM (weights 4.3, KV cache 1.0, compute 0.1; measured peak 5.8
over the desktop's own use). On an 8 GB laptop GPU that leaves about 1.4 GiB
for every other program, so one of them can push a call over the edge, and
Ollama then unloads the model. The client waits OOM_WAIT_S and asks again
(the model reloads). If that also runs out of memory and the prompt plus the
reply fit in FALLBACK_NUM_CTX, it asks once more with that context (half the
KV cache). Each step is noted on the reply (`notes`, `num_ctx`) and shown
next to the finding; a reply from the smaller context is not cached.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Callable, Generic, TypeVar

from pydantic import BaseModel, ValidationError

DEFAULT_MODEL = "ollama/llama3.1:8b"
MODEL_ENV = "GITTRACE_MODEL"
TIMEOUT_ENV = "GITTRACE_LLM_TIMEOUT"
NUM_CTX = 8192
FALLBACK_NUM_CTX = 4096
OOM_WAIT_S = 5.0
MAX_REPLY_TOKENS = 1024
TEMPERATURE = 0.1
SEED = 7
DEFAULT_TIMEOUT_S = 120.0

T = TypeVar("T", bound=BaseModel)


class LLMError(RuntimeError):
    attempts: int = 1           # set by ModelClient.complete
    seconds: float = 0.0


class ModelUnavailable(LLMError):
    pass


class ModelCallFailed(LLMError):
    pass


class OutOfMemory(ModelCallFailed):
    pass


class InvalidOutput(LLMError):
    def __init__(self, message: str, replies: tuple[str, ...]):
        super().__init__(message)
        self.replies = replies


def resolve_model(flag: str | None = None) -> str:
    """--model, then $GITTRACE_MODEL, then the default."""
    for candidate in (flag, os.environ.get(MODEL_ENV)):
        if candidate and candidate.strip():
            return candidate.strip()
    return DEFAULT_MODEL


def resolve_timeout() -> float:
    raw = os.environ.get(TIMEOUT_ENV)
    if not raw:
        return DEFAULT_TIMEOUT_S
    try:
        value = float(raw)
    except ValueError:
        raise LLMError(f"${TIMEOUT_ENV} must be a number of seconds, got {raw!r}") from None
    if value <= 0:
        raise LLMError(f"${TIMEOUT_ENV} must be positive, got {raw!r}")
    return value


def provider_model(model: str) -> str:
    """The name LiteLLM is called with (see the module docstring)."""
    if model.startswith("ollama/"):
        return "ollama_chat/" + model[len("ollama/"):]
    return model


def _is_ollama(model: str) -> bool:
    return model.startswith(("ollama/", "ollama_chat/"))


def _is_oom(exc: BaseException) -> bool:
    text = str(exc).lower()
    return "out of memory" in text or "unable to allocate" in text or "cudamalloc failed" in text


_OOM_HINT = "Close other programs that use the GPU, or pick a smaller model with --model."


@dataclass(frozen=True)
class Reply(Generic[T]):
    value: T
    raw: str
    attempts: int
    seconds: float
    num_ctx: int | None = None          # the context the reply came from (Ollama only)
    notes: tuple[str, ...] = ()         # recoveries, e.g. from running out of GPU memory


def _strip_fence(text: str) -> str:
    """Accept a reply wrapped in one ```json fence (models outside Ollama's
    constrained decoding often add one); anything else must be bare JSON."""
    s = text.strip()
    if s.startswith("```") and s.endswith("```") and s.count("```") == 2:
        s = s[3:-3]
        if s.lower().startswith("json"):
            s = s[4:]
    return s.strip()


def _problem(exc: ValidationError | json.JSONDecodeError) -> str:
    if isinstance(exc, json.JSONDecodeError):
        return f"not valid JSON ({exc.msg} at line {exc.lineno} column {exc.colno})"
    parts = []
    for err in exc.errors()[:5]:
        if err["type"] == "json_invalid":
            return f"not valid JSON ({err['msg'].removeprefix('Invalid JSON: ')})"
        where = ".".join(str(p) for p in err["loc"]) or "reply"
        parts.append(f"{where}: {err['msg']}")
    return "; ".join(parts)


class ModelClient:
    def __init__(self, model: str, *, timeout: float | None = None,
                 sleep: Callable[[float], None] | None = None):
        self.model = model
        self.timeout = resolve_timeout() if timeout is None else timeout
        self.sleep = time.sleep if sleep is None else sleep

    def _call(self, messages: list[dict], schema: type[BaseModel], num_ctx: int = NUM_CTX) -> str:
        try:
            import litellm
        except ImportError as exc:
            raise ModelUnavailable("litellm is not installed (pip install -r requirements.txt)") from exc
        litellm.suppress_debug_info = True
        kwargs = dict(
            model=provider_model(self.model), messages=messages, temperature=TEMPERATURE,
            seed=SEED, max_tokens=MAX_REPLY_TOKENS, timeout=self.timeout,
            response_format={"type": "json_schema", "json_schema": {
                "name": schema.__name__, "schema": schema.model_json_schema(), "strict": True}},
        )
        if _is_ollama(self.model):
            kwargs["num_ctx"] = num_ctx
        try:
            response = litellm.completion(**kwargs)
        except litellm.Timeout as exc:
            raise ModelCallFailed(f"{self.model} did not answer within {self.timeout:g} s "
                                  f"(set ${TIMEOUT_ENV} to wait longer)") from exc
        except (litellm.APIConnectionError, litellm.NotFoundError,
                litellm.AuthenticationError, litellm.PermissionDeniedError) as exc:
            hint = (" Is Ollama running (`ollama serve`) and the model pulled "
                    f"(`ollama pull {self.model.split('/', 1)[1]}`)?" if _is_ollama(self.model) else "")
            raise ModelUnavailable(f"cannot call {self.model}: {type(exc).__name__}: "
                                   f"{_first_line(exc)}.{hint}") from exc
        except Exception as exc:  # noqa: BLE001 - every other provider error, reported as is
            failed = OutOfMemory if _is_oom(exc) else ModelCallFailed
            raise failed(f"{self.model} call failed: {type(exc).__name__}: {_first_line(exc)}") from exc
        try:
            content = response.choices[0].message.content
        except (AttributeError, IndexError) as exc:
            raise ModelCallFailed(f"{self.model} returned a response with no message") from exc
        return content or ""

    def _send(self, messages: list[dict], schema: type[BaseModel], state: dict) -> str:
        """One call, recovering from the GPU running out of memory (see the
        module docstring). `state` holds the num_ctx in use, which stays
        reduced for the rest of this reply, and the notes."""
        try:
            return self._call(messages, schema, state["num_ctx"])
        except OutOfMemory:
            if not _is_ollama(self.model):
                raise
        self.sleep(OOM_WAIT_S)
        try:
            text = self._call(messages, schema, state["num_ctx"])
        except OutOfMemory as exc:
            last = exc
        else:
            state["notes"].append(f"the GPU ran out of memory; answered on a retry after {OOM_WAIT_S:g} s")
            return text
        from gittrace.llm.context import estimate_tokens      # context imports this module
        needed = estimate_tokens("".join(m["content"] for m in messages)) + MAX_REPLY_TOKENS
        if state["num_ctx"] <= FALLBACK_NUM_CTX or needed > FALLBACK_NUM_CTX:
            why = ("" if state["num_ctx"] <= FALLBACK_NUM_CTX else
                   f"; the prompt and reply (~{needed} tokens) do not fit num_ctx {FALLBACK_NUM_CTX}, "
                   "so no smaller context was tried")
            raise OutOfMemory(f"{self.model} ran out of GPU memory twice at num_ctx {state['num_ctx']}"
                              f"{why}. {_OOM_HINT}") from last
        try:
            text = self._call(messages, schema, FALLBACK_NUM_CTX)
        except OutOfMemory as exc:
            raise OutOfMemory(f"{self.model} ran out of GPU memory twice at num_ctx {state['num_ctx']} "
                              f"and again at {FALLBACK_NUM_CTX}. {_OOM_HINT}") from exc
        state["notes"].append(f"the GPU ran out of memory twice at num_ctx {state['num_ctx']}; answered "
                              f"with num_ctx {FALLBACK_NUM_CTX}, which held the whole prompt "
                              f"(~{needed} tokens with the reply)")
        state["num_ctx"] = FALLBACK_NUM_CTX
        return text

    def complete(self, system: str, user: str, schema: type[T]) -> Reply[T]:
        """One validated reply, with one retry on invalid output. An error
        raised here carries the attempts made and the seconds spent."""
        start = time.perf_counter()
        state: dict = {"num_ctx": NUM_CTX, "notes": [], "attempt": 1}
        try:
            return self._complete(system, user, schema, state, start)
        except LLMError as exc:
            exc.attempts, exc.seconds = state["attempt"], time.perf_counter() - start
            raise

    def _complete(self, system: str, user: str, schema: type[T], state: dict, start: float) -> Reply[T]:
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        replies: list[str] = []
        for attempt in (1, 2):
            state["attempt"] = attempt
            raw = self._send(messages, schema, state)
            replies.append(raw)
            try:
                value = schema.model_validate_json(_strip_fence(raw))
            except (ValidationError, json.JSONDecodeError) as exc:
                problem = _problem(exc)
                if attempt == 2:
                    raise InvalidOutput(
                        f"{self.model} returned invalid output twice; last problem: {problem}",
                        tuple(replies)) from exc
                messages = messages + [
                    {"role": "assistant", "content": raw},
                    {"role": "user", "content": (
                        f"That reply was rejected: {problem}. Reply again with only the JSON "
                        f"object, with exactly the fields {sorted(schema.model_fields)}.")},
                ]
                continue
            return Reply(value=value, raw=raw, attempts=attempt, seconds=time.perf_counter() - start,
                         num_ctx=state["num_ctx"] if _is_ollama(self.model) else None,
                         notes=tuple(state["notes"]))
        raise AssertionError("unreachable")


def _first_line(exc: BaseException) -> str:
    text = str(exc).strip()
    return text.splitlines()[0][:300] if text else "no detail"
