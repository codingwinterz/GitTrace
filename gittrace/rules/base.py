"""
gittrace.rules.base — what a rule is, and what it produces.

Rules detect; nothing else in GitTrace decides whether something is a
finding. A rule looks at one call site (CallSite: the full callee name, plus an
ArgFact for every argument) or one string constant bound to a name
(AssignFact), and returns a Match or None. Both inputs are the
language-neutral records from gittrace.languages.base, so a rule never sees a
syntax tree; a language plug-in that produces those records can reuse a rule
by listing its language in `languages` (the callee names a rule matches, such
as `subprocess.run`, are what make it language-specific).

Every rule module documents its rule_id, what it matches, and what it
deliberately does not.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from gittrace.languages.base import ArgFact, AssignFact, CallSite, SiteFacts

SEVERITIES = ("info", "low", "medium", "high", "critical")


def severity_rank(level: str) -> int:
    return SEVERITIES.index(level)


@dataclass(frozen=True)
class Match:
    rule_id: str
    category: str
    title: str
    base_severity: str
    function_id: str            # the function (or <module>) the site is in
    site: SiteFacts
    message: str
    callee: str | None = None   # full dotted name, for call rules
    evidence: tuple[str, ...] = ()
    param_derived: bool = False
    params: tuple[str, ...] = ()
    # False for rules whose risk does not depend on who can reach the code
    # (a hardcoded secret is exposed by the repository, not by a route).
    flow_sensitive: bool = True

    @property
    def sink_id(self) -> str:
        return f"{self.site.file}::{self.site.line}::{self.site.column}"


class Rule:
    rule_id: ClassVar[str]
    category: ClassVar[str]
    title: ClassVar[str]
    base_severity: ClassVar[str]
    languages: ClassVar[tuple[str, ...]] = ("python",)
    flow_sensitive: ClassVar[bool] = True

    def check_call(self, call: CallSite) -> Match | None:
        return None

    def check_assignment(self, assignment: AssignFact) -> Match | None:
        return None

    def match_call(self, call: CallSite, message: str, arg: ArgFact | None = None,
                   evidence: tuple[str, ...] = ()) -> Match:
        params = arg.params if arg is not None else ()
        return Match(
            rule_id=self.rule_id, category=self.category, title=self.title,
            base_severity=self.base_severity, function_id=call.caller_id,
            site=call.site, message=message, callee=call.dotted,  # type: ignore[arg-type]
            evidence=evidence + describe(arg), param_derived=bool(params),
            params=params, flow_sensitive=self.flow_sensitive,
        )


def describe(arg: ArgFact | None) -> tuple[str, ...]:
    """Human-readable evidence for how an argument was built."""
    if arg is None:
        return ()
    out = []
    if arg.kind == "built":
        out.append({
            "fstring": "f-string", "concat": "string concatenation (+)",
            "percent": "%-formatting", "format": ".format()", "join": ".join()",
        }.get(arg.how or "", "built string"))
    elif arg.kind == "param":
        out.append("parameter passed through unchanged")
    elif arg.kind == "other":
        out.append("non-constant value")
    if arg.via:
        out.append(f"via variable `{arg.via}`")
    if arg.params:
        out.append("derived from parameter " + ", ".join(f"`{p}`" for p in arg.params))
    return tuple(out)


def last_name(dotted: str) -> str:
    return dotted.rsplit(".", 1)[-1]
