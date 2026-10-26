"""
gittrace.llm.schemas — the shape every model reply must have.

A reply is accepted only if it validates against its task's schema: no
extra fields (so a reply cannot carry new findings, a different finding id
or anything else the schema does not name), enumerated verdicts, a bounded
severity adjustment, and a verdict consistent with the reply's own account
of where the values come from. Text fields are stripped of control characters, so a
reply cannot move the terminal cursor or recolour the report.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

VERDICTS = ("likely_real", "likely_harmless", "uncertain")
MIN_ADJUSTMENT = -2
MAX_ADJUSTMENT = 1
MAX_REASON = 500
MAX_FIX = 6000

# C0/C1 control characters (ESC among them), except tab and newline.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def clean_text(value: str, *, keep_newlines: bool) -> str:
    value = _CONTROL.sub("", value.replace("\r\n", "\n"))
    if not keep_newlines:
        value = " ".join(value.split())
    return value


SOURCES = ("constant", "internal", "attacker", "unknown")
MAX_VALUES = 10


class ValueSource(BaseModel):
    """One value that flows into the flagged call, and where the model thinks it comes from."""

    model_config = ConfigDict(extra="forbid")

    value: str = Field(min_length=1, max_length=200)
    source: Literal["constant", "internal", "attacker", "unknown"]

    @field_validator("value")
    @classmethod
    def _value(cls, value: str) -> str:
        value = clean_text(value, keep_newlines=False)
        if not value:
            raise ValueError("value is empty")
        return value


class TriageReply(BaseModel):
    """The model's view of one finding. It cannot create or remove findings.

    `values` comes first: Ollama generates the fields in schema order, so the
    model states where each value comes from before it gives a verdict."""

    model_config = ConfigDict(extra="forbid")

    values: list[ValueSource] = Field(min_length=1, max_length=MAX_VALUES)
    verdict: Literal["likely_real", "likely_harmless", "uncertain"]
    reason: str = Field(min_length=1, max_length=MAX_REASON)
    severity_adjustment: int = Field(ge=MIN_ADJUSTMENT, le=MAX_ADJUSTMENT)
    # Replacement text for the fix region named in the prompt, or null.
    fix_code: str | None = Field(max_length=MAX_FIX)

    @field_validator("reason")
    @classmethod
    def _reason(cls, value: str) -> str:
        value = clean_text(value, keep_newlines=False)
        if not value:
            raise ValueError("reason is empty")
        return value

    @field_validator("fix_code")
    @classmethod
    def _fix(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = clean_text(value, keep_newlines=True)
        return value if value.strip() else None

    @model_validator(mode="after")
    def _consistent(self) -> "TriageReply":
        if self.verdict == "likely_harmless" and self.severity_adjustment > 0:
            raise ValueError("a likely_harmless verdict cannot raise the severity")
        if self.verdict == "likely_harmless":
            risky = [v.value for v in self.values if v.source in ("attacker", "unknown")]
            if risky:
                raise ValueError("likely_harmless needs every value to be constant or internal, "
                                 f"but these are attacker or unknown: {', '.join(risky[:3])}")
        return self
