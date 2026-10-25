"""Deterministic vulnerability rules, one per module. See gittrace.rules.base."""

from __future__ import annotations

from gittrace.languages.base import AssignFact, CallSite
from gittrace.rules.base import Match, Rule
from gittrace.rules.code_eval import CodeEval
from gittrace.rules.command_injection import CommandInjection
from gittrace.rules.deserialization import UnsafeDeserialization
from gittrace.rules.hardcoded_secret import HardcodedSecret
from gittrace.rules.sql_injection import SqlInjection

ALL_RULES: tuple[Rule, ...] = (
    SqlInjection(), CodeEval(), CommandInjection(), UnsafeDeserialization(), HardcodedSecret(),
)


def rules_for(language: str) -> tuple[Rule, ...]:
    return tuple(r for r in ALL_RULES if language in r.languages)


def run_rules(rules, calls: list[CallSite], assignments: list[AssignFact]) -> list[Match]:
    """Every match, in source order. Calls resolved to project code are never
    sinks: whatever is dangerous happens inside them, where it is checked."""
    matches: list[Match] = []
    for call in calls:
        if call.resolved or call.origin == "class" or call.site is None:
            continue
        for rule in rules:
            found = rule.check_call(call)
            if found is not None:
                matches.append(found)
    for assignment in assignments:
        for rule in rules:
            found = rule.check_assignment(assignment)
            if found is not None:
                matches.append(found)
    matches.sort(key=lambda m: (m.site.file, m.site.line, m.site.column, m.rule_id))
    return matches
