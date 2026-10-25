"""
gittrace.core.severity — the deterministic severity of a finding.

A finding's score starts from its rule's base severity and moves by fixed
amounts; the final level is read off the score. The same inputs always give
the same severity, and every step is recorded as a reason.

    base:  critical 8 · high 6 · medium 4 · low 2 · info 0

    flow-sensitive rules only (all but hardcoded secrets):
      reachable from an unauthenticated endpoint ........ +3
      else reachable only from authenticated endpoints .. +1
      else not reachable from any endpoint .............. -2
      the dangerous value derives from a parameter ...... +1
      blast radius (upstream callers + endpoints) >= 5 .. +1

    level: score >= 9 critical · 7-8 high · 4-6 medium · 2-3 low · <= 1 info

Endpoints whose path prefix could not be resolved (prefix_resolved=false)
count as reachable; the finding is flagged `uncertain` when every endpoint
that decided its reachability adjustment is one of those.
"""

from __future__ import annotations

from dataclasses import dataclass

BASE_SCORE = {"critical": 8, "high": 6, "medium": 4, "low": 2, "info": 0}
UNAUTHENTICATED = 3
AUTHENTICATED_ONLY = 1
UNREACHABLE = -2
PARAM_DERIVED = 1
BLAST_RADIUS = 1
BLAST_RADIUS_THRESHOLD = 5


def level(score: int) -> str:
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    if score >= 2:
        return "low"
    return "info"


@dataclass(frozen=True)
class Exposure:
    """What the graph says about who can reach a finding."""

    unauthenticated: int = 0           # unauthenticated endpoints that reach it
    authenticated: int = 0             # authenticated endpoints that reach it
    callers: int = 0                   # upstream callers of its function
    decided_by_unresolved_prefix: bool = False

    @property
    def endpoints(self) -> int:
        return self.unauthenticated + self.authenticated

    @property
    def blast_radius(self) -> int:
        return self.callers + self.endpoints


@dataclass(frozen=True)
class Severity:
    level: str
    score: int
    reasons: tuple[str, ...]
    uncertain: bool


def score(base_severity: str, flow_sensitive: bool, param_derived: bool, exposure: Exposure) -> Severity:
    total = BASE_SCORE[base_severity]
    reasons = [f"base severity {base_severity} ({total})"]
    if not flow_sensitive:
        reasons.append("not adjusted for reachability (rule is not flow-sensitive)")
        return Severity(level(total), total, tuple(reasons), False)

    if exposure.unauthenticated:
        total += UNAUTHENTICATED
        reasons.append(f"reachable from {exposure.unauthenticated} unauthenticated endpoint(s) (+{UNAUTHENTICATED})")
    elif exposure.authenticated:
        total += AUTHENTICATED_ONLY
        reasons.append(f"reachable only from {exposure.authenticated} authenticated endpoint(s) (+{AUTHENTICATED_ONLY})")
    else:
        total += UNREACHABLE
        reasons.append(f"not reachable from any endpoint ({UNREACHABLE})")
    if param_derived:
        total += PARAM_DERIVED
        reasons.append(f"input derives from a function parameter (+{PARAM_DERIVED})")
    if exposure.blast_radius >= BLAST_RADIUS_THRESHOLD:
        total += BLAST_RADIUS
        reasons.append(
            f"blast radius {exposure.blast_radius} >= {BLAST_RADIUS_THRESHOLD} (+{BLAST_RADIUS})")
    if exposure.decided_by_unresolved_prefix:
        reasons.append("uncertain: the deciding endpoints' route prefixes were not fully resolved")
    return Severity(level(total), total, tuple(reasons), exposure.decided_by_unresolved_prefix)
