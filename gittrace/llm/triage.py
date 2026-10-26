"""
gittrace.llm.triage — the model's opinion on each scan finding.

For every finding the rules produced, the model returns a TriageReply:

    values              each value flowing into the flagged call, and its source
                        (constant | internal | attacker | unknown)
    verdict             likely_real | likely_harmless | uncertain
    reason              a sentence or two
    severity_adjustment -2..+1, added to the rules' score; the rules' score and
                        the adjustment are both kept, and shown side by side
    fix_code            optional replacement for the fix region; GitTrace turns
                        it into a diff and checks it (gittrace.llm.fix)

The model cannot create, remove or rename findings: it is asked about one
finding at a time, by GitTrace, and its reply has no field for anything
else. A likely_harmless finding is still a finding; the report lists it in
its own section with the model's reason. The `--fail-on` gate uses the
rules' severity only, so code that talks the model into a downgrade cannot
turn a failing CI run into a passing one.

Errors: ModelUnavailable (the model cannot be called at all) propagates and
stops the scan. A finding whose call times out or fails, or whose reply is
invalid twice, gets a Triage with `error` set, which the report shows next
to that finding; the other findings are still triaged.

When the GPU ran out of memory and the client recovered (gittrace.llm.client),
`call_notes` says how and `num_ctx` which context answered; the report shows
both next to the finding. A reply from a reduced context is not cached, so the
next scan asks again with the full one.
"""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from pydantic import ValidationError

from gittrace.core.severity import level
from gittrace.llm.cache import Cache, cache_key
from gittrace.llm.client import NUM_CTX, InvalidOutput, ModelCallFailed, ModelClient
from gittrace.llm.context import ContextBuilder
from gittrace.llm.fix import NO_FIX, FixCheck, check_fix
from gittrace.llm.prompts import PROMPT_VERSION, TRIAGE_SYSTEM
from gittrace.llm.schemas import VERDICTS, TriageReply

TASK = "triage"


@dataclass(frozen=True)
class Triage:
    finding_id: str
    model: str
    prompt_version: str
    verdict: str | None
    reason: str | None
    values: tuple[tuple[str, str], ...]     # (value, source), as the model sees it
    adjustment: int
    score: int                    # the rules' score, unchanged
    adjusted_score: int
    adjusted_severity: str
    fix: FixCheck | None          # None when the model offered no fix
    cached: bool
    seconds: float                # model time; 0 for a cache hit
    attempts: int
    context_tokens: int
    notes: tuple[str, ...] = ()               # what the context builder cut
    error: str | None = None
    call_notes: tuple[str, ...] = ()          # how a failed model call was recovered
    num_ctx: int | None = None                # the context that answered (Ollama)

    def to_dict(self) -> dict:
        return {
            "model": self.model, "prompt_version": self.prompt_version,
            "verdict": self.verdict, "reason": self.reason,
            "values": [{"value": v, "source": s} for v, s in self.values],
            "severity_adjustment": self.adjustment,
            "rules_score": self.score, "adjusted_score": self.adjusted_score,
            "adjusted_severity": self.adjusted_severity,
            "fix": (self.fix.to_dict() if self.fix is not None
                    else {"valid": False, "diff": None, "problem": "the model offered no fix"}),
            "cached": self.cached, "seconds": round(self.seconds, 2), "attempts": self.attempts,
            "context_tokens": self.context_tokens, "context_notes": list(self.notes),
            "num_ctx": self.num_ctx, "call_notes": list(self.call_notes),
            "error": self.error,
        }


class Triager:
    def __init__(self, analysis, client: ModelClient, cache: Cache | None = None):
        self.root = Path(analysis.root)
        self.client = client
        self.cache = cache
        self.builder = ContextBuilder(analysis)

    def _cached(self, key: str) -> TriageReply | None:
        if self.cache is None:
            return None
        record = self.cache.get(key)
        if record is None:
            return None
        try:
            return TriageReply.model_validate(record.get("reply"))
        except ValidationError as exc:
            self.cache.reject(key, str(exc).splitlines()[0])
            return None

    def triage(self, finding) -> Triage:
        ctx = self.builder.build(finding)
        key = cache_key(TASK, self.client.model, PROMPT_VERSION, ctx.prompt)
        base = dict(finding_id=finding.id, model=self.client.model, prompt_version=PROMPT_VERSION,
                    score=finding.score, context_tokens=ctx.tokens, notes=ctx.notes)
        reply = self._cached(key)
        cached, seconds, attempts, call_notes, num_ctx = reply is not None, 0.0, 0, (), None
        if reply is None:
            try:
                answer = self.client.complete(TRIAGE_SYSTEM, ctx.prompt, TriageReply)
            except (InvalidOutput, ModelCallFailed) as exc:
                return Triage(**base, verdict=None, reason=None, values=(), adjustment=0,
                              adjusted_score=finding.score, adjusted_severity=finding.severity,
                              fix=None, cached=False, seconds=exc.seconds, attempts=exc.attempts,
                              error=str(exc))
            reply, seconds, attempts = answer.value, answer.seconds, answer.attempts
            call_notes, num_ctx = answer.notes, answer.num_ctx
            if self.cache is not None and num_ctx in (None, NUM_CTX):
                self.cache.put(key, {"task": TASK, "model": self.client.model,
                                     "prompt_version": PROMPT_VERSION, "finding_id": finding.id,
                                     "reply": reply.model_dump(), "raw": answer.raw,
                                     "attempts": attempts, "seconds": round(seconds, 2),
                                     "created": time.strftime("%Y-%m-%dT%H:%M:%S%z")})

        fix = None
        if reply.fix_code is not None:
            if ctx.fix_region is None:
                fix = FixCheck(False, None, "no fix region was offered for this finding")
            else:
                fix = check_fix(self.root, finding.file, ctx.fix_region, reply.fix_code,
                                self.builder.secrets)
        adjusted = finding.score + reply.severity_adjustment
        # Test code is reported at info whatever its score (core.scan).
        adjusted_level = "info" if finding.in_tests else level(adjusted)
        return Triage(**base, verdict=reply.verdict, reason=reply.reason,
                      values=tuple((v.value, v.source) for v in reply.values),
                      adjustment=reply.severity_adjustment, adjusted_score=adjusted,
                      adjusted_severity=adjusted_level, fix=fix, cached=cached,
                      seconds=seconds, attempts=attempts, call_notes=call_notes, num_ctx=num_ctx)


@dataclass
class TriageRun:
    model: str
    results: dict[str, Triage] = field(default_factory=dict)
    seconds: float = 0.0
    prompt_version: str = PROMPT_VERSION

    @property
    def errors(self) -> list[Triage]:
        return [t for t in self.results.values() if t.error]

    @property
    def recovered(self) -> list[Triage]:
        """Answered after a failed call (the GPU ran out of memory)."""
        return [t for t in self.results.values() if t.call_notes]

    def meta(self) -> dict:
        verdicts = Counter(t.verdict for t in self.results.values() if t.verdict)
        return {
            "enabled": True, "model": self.model, "prompt_version": self.prompt_version,
            "triaged": len(self.results),
            "cached": sum(1 for t in self.results.values() if t.cached),
            "errors": len(self.errors),
            "recovered": len(self.recovered),
            "reduced_context": sum(1 for t in self.results.values()
                                   if t.num_ctx is not None and t.num_ctx < NUM_CTX),
            "by_verdict": {v: verdicts.get(v, 0) for v in VERDICTS},
            "valid_fixes": sum(1 for t in self.results.values() if t.fix is not None and t.fix.valid),
            "seconds": round(self.seconds, 2),
        }

    def to_dicts(self) -> dict[str, dict]:
        return {fid: t.to_dict() for fid, t in self.results.items()}


def triage_findings(analysis, findings, client: ModelClient, cache: Cache | None = None,
                    progress: Callable[[int, int, object], None] | None = None) -> TriageRun:
    """Triage each finding in order. ModelUnavailable propagates."""
    triager = Triager(analysis, client, cache)
    run = TriageRun(model=client.model)
    start = time.perf_counter()
    for i, finding in enumerate(findings, 1):
        if progress is not None:
            progress(i, len(findings), finding)
        run.results[finding.id] = triager.triage(finding)
    run.seconds = time.perf_counter() - start
    return run


__all__ = ["NO_FIX", "Triage", "TriageRun", "Triager", "triage_findings"]
