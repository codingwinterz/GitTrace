"""
gittrace.core.owner — who last changed a finding's line, from `git blame`.

One `git blame --porcelain` per file, with one -L range per finding line.
Outside a git repository (or without git installed) every lookup quietly
returns None. A line that is not committed yet has status "uncommitted" and
no author.
"""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)
_TIMEOUT = 30
_ZERO = "0" * 40


@dataclass(frozen=True)
class Owner:
    status: str                    # committed | uncommitted
    author: str | None = None
    email: str | None = None
    commit: str | None = None
    date: str | None = None        # author date, ISO 8601 UTC
    summary: str | None = None


def _git(root: Path, *args: str) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(["git", "-C", str(root), *args], capture_output=True,
                              text=True, encoding="utf-8", errors="replace", timeout=_TIMEOUT)
    except (OSError, subprocess.SubprocessError):
        return None


class Blamer:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        probe = _git(self.root, "rev-parse", "--is-inside-work-tree")
        self.enabled = probe is not None and probe.returncode == 0 and probe.stdout.strip() == "true"

    def blame(self, file: str, lines: list[int]) -> dict[int, Owner]:
        """line -> Owner for the given lines of one project-relative file."""
        if not self.enabled or not lines:
            return {}
        ranges = [arg for n in sorted(set(lines)) for arg in ("-L", f"{n},{n}")]
        out = _git(self.root, "blame", "--porcelain", *ranges, "--", file)
        if out is None or out.returncode != 0:
            if out is not None:
                log.info("git blame %s: %s", file, out.stderr.strip())
            return {}
        return _parse_porcelain(out.stdout)


def _parse_porcelain(text: str) -> dict[int, Owner]:
    commits: dict[str, dict[str, str]] = {}
    result: dict[int, Owner] = {}
    current: dict[str, str] | None = None
    sha, final_line = "", 0
    for raw in text.splitlines():
        if raw.startswith("\t"):
            info = commits.get(sha, {})
            if sha == _ZERO:
                result[final_line] = Owner(status="uncommitted")
            else:
                when = info.get("author-time")
                result[final_line] = Owner(
                    status="committed",
                    author=info.get("author"),
                    email=info.get("author-mail", "").strip("<>") or None,
                    commit=sha,
                    date=(datetime.fromtimestamp(int(when), timezone.utc).isoformat(timespec="seconds")
                          if when and when.isdigit() else None),
                    summary=info.get("summary"),
                )
            current = None
            continue
        parts = raw.split(" ")
        if current is None and len(parts) >= 3 and len(parts[0]) == 40:
            sha, final_line = parts[0], int(parts[2])
            current = commits.setdefault(sha, {})
            continue
        if current is not None:
            key, _, value = raw.partition(" ")
            current[key] = value
    return result
