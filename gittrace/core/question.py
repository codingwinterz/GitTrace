"""
gittrace.core.question — what a natural-language question refers to.

Pulls the CVE id, function name and service name out of a question, matching
names against the live graph so any function or service in it is recognized.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from functools import cached_property

from gittrace.graph import connection


def extract_cve_id(text: str) -> str | None:
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

_ENTITY_CACHE: dict[tuple[str, str], tuple[float, list[str]]] = {}
_ENTITY_TTL_S = 60.0


def graph_names(label: str, prop: str = "name") -> list[str]:
    """All distinct values of a node property for a label, cached briefly.

    Values are returned exactly as stored. They used to be lowercased, which
    meant a name like Repo.get_user came back as repo.get_user and then
    matched nothing when handed to a tool.

    Returns an empty list on any DB failure so callers can fall back to the
    static lists (offline demos, unit tests without a graph).
    """
    now = time.monotonic()
    key = (label, prop)
    cached = _ENTITY_CACHE.get(key)
    if cached and now - cached[0] < _ENTITY_TTL_S:
        return cached[1]
    try:
        rows = connection.get_graph().query(
            f"MATCH (n:{label}) RETURN DISTINCT n.{prop}"
        ).result_set
        names = sorted({str(r[0]) for r in rows if r and r[0]})
    except Exception:  # noqa: BLE001 - degrade to the static candidate lists
        names = []
    _ENTITY_CACHE[key] = (now, names)
    return names


# Identifier-shaped words: snake_case functions, dotted qualified names and
# hyphenated service names.
_TOKEN_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.\-]*")


def _first_named(text: str, candidates: list[str]) -> str | None:
    """The first word of `text` that exactly equals one of `candidates`.

    Words are compared whole and case-sensitively, so 'token' never matches
    inside 'refresh_token' and 'validate_token_v2' is not 'validate_token'.
    """
    known = set(candidates)
    for word in _TOKEN_RE.findall(text):
        word = word.rstrip(".-")
        if word in known:
            return word
    return None


def extract_function_name(question: str) -> str | None:
    return _first_named(question, graph_names("Function") or _STATIC_FUNCTIONS)


def extract_public_service(question: str) -> str | None:
    return _first_named(question, graph_names("Service") or _STATIC_SERVICES)


def function_for_cve(cve_id: str) -> str | None:
    """Name of the Function a CVE affects.

    Lets questions that name only the CVE ("who owns the vulnerable function
    in CVE-2026-4421?") reach a tool at all. The tool call itself is scoped by
    cve_id, so this name is only a label and never used to look the function up.
    """
    try:
        rows = connection.get_graph().query(
            "MATCH (c:CVE {id: $cve_id})-[:AFFECTS]->(f:Function) "
            "RETURN f.name AS name ORDER BY name LIMIT 1",
            params={"cve_id": cve_id},
        ).result_set
    except Exception:  # noqa: BLE001 - no CVE context is better than a crash
        return None
    return str(rows[0][0]) if rows and rows[0] and rows[0][0] else None


@dataclass
class QuestionContext:
    """What the keyword classifier extracted from a question."""

    question: str
    cve_id: str | None
    function_name: str | None
    service_name: str | None

    @classmethod
    def from_question(cls, question: str) -> QuestionContext:
        return cls(
            question=question,
            cve_id=extract_cve_id(question),
            function_name=extract_function_name(question),
            service_name=extract_public_service(question),
        )

    def mentions(self, keywords: tuple[str, ...]) -> bool:
        q = self.question.lower()
        return any(k in q for k in keywords)

    @cached_property
    def target_function(self) -> str | None:
        """The function the question names, else the one its CVE affects.

        Lazy, so questions that never need a target don't pay a graph
        round-trip for it.
        """
        if self.function_name:
            return self.function_name
        if self.cve_id:
            return function_for_cve(self.cve_id)
        return None
