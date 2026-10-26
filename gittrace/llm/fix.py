"""
gittrace.llm.fix — a suggested fix, as a unified diff that has been checked.

The model does not write the diff. It returns replacement text for the fix
region (the flagged statement and where its value is built, named in the
prompt). Its indentation is re-based on the region's first line (the model
often drops it), keeping the relative indentation of its lines.
A small model rarely gets unified-diff hunk headers and context lines exactly
right, whereas GitTrace can: it splices the replacement into the file's real
text (keeping its line endings) and builds the diff with difflib. The diff is
then checked:

  - the replacement is not empty, has no copied line numbers, and changes
    something;
  - if the original file parses as Python (ast), the patched file must too;
  - `git apply --check` accepts it against a copy of the file in a temporary
    directory, outside any repository.

Nothing is ever written to the project. The diff shown to the user masks
hardcoded secrets, like every report; the diff checked is the real one.
"""

from __future__ import annotations

import ast
import difflib
import os
import re
import subprocess
import tempfile
import textwrap
from dataclasses import dataclass
from pathlib import Path

from gittrace.rules.hardcoded_secret import mask

NO_FIX = "no valid fix suggested"
_NUMBERED = re.compile(r"^\s*(>>)?\s*\d+\s+\|")


@dataclass(frozen=True)
class FixCheck:
    valid: bool
    diff: str | None         # masked unified diff, when valid
    problem: str | None      # why it is not valid

    def to_dict(self) -> dict:
        return {"valid": self.valid, "diff": self.diff, "problem": self.problem}


def _invalid(problem: str) -> FixCheck:
    return FixCheck(False, None, problem)


def _diff(old: list[str], new: list[str], rel: str) -> str:
    out = []
    for line in difflib.unified_diff(old, new, fromfile=f"a/{rel}", tofile=f"b/{rel}", n=3):
        out.append(line)
        if not line.endswith("\n"):
            # difflib does not mark a last line without a newline; git needs it.
            out.append("\n\\ No newline at end of file\n")
    return "".join(out)


def git_apply_check(original: bytes, rel: str, patch: str) -> str | None:
    """None if `git apply --check` accepts `patch` for a copy of the file, else why not."""
    with tempfile.TemporaryDirectory(prefix="gittrace-fix-") as tmp:
        target = Path(tmp) / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(original)
        patch_file = Path(tmp) / "fix.patch"
        patch_file.write_bytes(patch.encode("utf-8"))
        # Never let git discover a repository above the temporary directory.
        env = {**os.environ, "GIT_CEILING_DIRECTORIES": str(Path(tmp).parent)}
        try:
            done = subprocess.run(["git", "apply", "--check", "fix.patch"], cwd=tmp, env=env,
                                  capture_output=True, text=True, encoding="utf-8",
                                  errors="replace", timeout=30)
        except FileNotFoundError:
            return "git is not installed, so the diff could not be checked"
        except subprocess.TimeoutExpired:
            return "git apply --check timed out"
        if done.returncode != 0:
            detail = (done.stderr or done.stdout).strip().splitlines()
            return "git apply --check rejected it: " + (detail[0] if detail else f"exit {done.returncode}")
    return None


def check_fix(root: Path, rel: str, region: tuple[int, int], replacement: str,
              secrets: list[str] = ()) -> FixCheck:
    try:
        original = (Path(root) / rel).read_bytes()
    except OSError as exc:
        return _invalid(f"cannot read {rel}: {exc}")
    try:
        text = original.decode("utf-8")
    except UnicodeDecodeError:
        return _invalid(f"{rel} is not UTF-8")
    lines = text.splitlines(keepends=True)
    first, last = region
    if not (1 <= first <= last <= len(lines)):
        return _invalid(f"fix region {first}-{last} is outside the file ({len(lines)} lines)")
    eol = "\r\n" if lines[first - 1].endswith("\r\n") else "\n"

    body = replacement.replace("\r\n", "\n").strip("\n")
    if not body.strip():
        return _invalid("the suggested fix is empty")
    if any(_NUMBERED.match(line) for line in body.split("\n")):
        return _invalid("the suggested fix contains copied line numbers")
    # The model saw secrets masked; a line it copied unchanged must stay unchanged.
    for value in sorted(secrets, key=len, reverse=True):
        body = body.replace(mask(value), value)
    first_line = lines[first - 1]
    indent = first_line[:len(first_line) - len(first_line.lstrip(" \t"))]
    body = "\n".join(indent + line if line.strip() else "" for line in
                     textwrap.dedent(body).split("\n"))
    new_region = [line + eol for line in body.split("\n")]
    if last == len(lines) and not lines[-1].endswith(("\n", "\r")):
        new_region[-1] = new_region[-1][:-len(eol)]        # keep a missing final newline missing
    patched = lines[:first - 1] + new_region + lines[last:]
    if patched == lines:
        return _invalid("the suggested fix changes nothing")

    try:
        ast.parse(text)
        parses = True
    except (SyntaxError, ValueError):
        parses = False                  # e.g. Python 2: nothing to compare against
    if parses:
        try:
            ast.parse("".join(patched))
        except (SyntaxError, ValueError) as exc:
            where = f" (line {exc.lineno})" if getattr(exc, "lineno", None) else ""
            return _invalid(f"the patched file does not parse{where}: {getattr(exc, 'msg', exc)}")

    patch = _diff(lines, patched, rel)
    problem = git_apply_check(original, rel, patch)
    if problem is not None:
        return _invalid(problem)
    shown = patch
    for value in sorted(secrets, key=len, reverse=True):
        shown = shown.replace(value, mask(value))
    return FixCheck(True, shown, None)
