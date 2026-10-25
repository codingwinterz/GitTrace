"""
GT-CMDI-001 — shell commands built from non-constant values.

Matches:
  - subprocess.run / call / check_call / check_output / Popen with
    `shell=True` (the literal True) and a non-constant command (first
    positional or args=);
  - functions that always use a shell: os.system, os.popen,
    subprocess.getoutput, subprocess.getstatusoutput,
    asyncio.create_subprocess_shell, with a non-constant command.

Not findings: a constant command; subprocess without shell=True (an argument
list is not parsed by a shell); `shell=` set to anything but the literal True.
"""

from __future__ import annotations

from gittrace.languages.base import CallSite
from gittrace.rules.base import Match, Rule

SHELL_OPTIONAL = frozenset({
    "subprocess.run", "subprocess.call", "subprocess.check_call",
    "subprocess.check_output", "subprocess.Popen",
})
SHELL_ALWAYS = frozenset({
    "os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput",
    "asyncio.create_subprocess_shell",
})


class CommandInjection(Rule):
    rule_id = "GT-CMDI-001"
    category = "command-injection"
    title = "Shell command built from a non-constant value"
    base_severity = "high"

    def check_call(self, call: CallSite) -> Match | None:
        evidence: tuple[str, ...] = ()
        if call.dotted in SHELL_OPTIONAL:
            shell = call.kwarg("shell")
            if shell is None or not shell.is_literal or shell.value is not True:
                return None
            evidence = ("shell=True",)
        elif call.dotted not in SHELL_ALWAYS:
            return None
        command = call.argument(0, "args", "cmd", "command")
        if command is None or command.is_literal:
            return None
        return self.match_call(
            call, f"`{call.dotted}` passes a non-constant command to a shell.", command, evidence,
        )
