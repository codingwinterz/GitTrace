"""
GT-EVAL-001 — eval / exec / compile on a non-constant value.

Matches the builtins eval(), exec() and compile() (also spelled builtins.eval
etc.) when their source argument (first positional, or source= / expression=)
is anything other than a constant. `eval("1 + 1")` is not a finding.
`re.compile(...)` and other functions that merely share the name are not
matched: the full callee name must be the builtin.
"""

from __future__ import annotations

from gittrace.languages.base import CallSite
from gittrace.rules.base import Match, Rule

EVAL_FUNCTIONS = frozenset({
    "eval", "exec", "compile", "builtins.eval", "builtins.exec", "builtins.compile",
})


class CodeEval(Rule):
    rule_id = "GT-EVAL-001"
    category = "code-injection"
    title = "Dynamic code evaluation"
    base_severity = "high"

    def check_call(self, call: CallSite) -> Match | None:
        if call.dotted not in EVAL_FUNCTIONS or call.origin not in ("builtin", "import"):
            return None
        source = call.argument(0, "source", "expression")
        if source is None or source.is_literal:
            return None
        return self.match_call(
            call, f"`{call.dotted}` executes code from a non-constant value.", source,
        )
