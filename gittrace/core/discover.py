"""
gittrace.core.discover — find the source files to scan in a project folder.

Skipped: VCS and tool directories (.git, caches), virtualenvs (by name, and any
directory holding a pyvenv.cfg), node_modules, site-packages, build/dist, and
anything the project's .gitignore files exclude. Nested .gitignore files apply
below their own directory, and a deeper file overrides a shallower one, as in
git. Symlinked directories are not followed.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import pathspec

log = logging.getLogger(__name__)

SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn",
    "venv", ".venv",
    "node_modules", "__pycache__", "site-packages",
    "build", "dist",
    ".tox", ".nox", ".eggs", ".mypy_cache", ".pytest_cache", ".ruff_cache",
})


def _load_gitignore(directory: Path) -> pathspec.GitIgnoreSpec | None:
    path = directory / ".gitignore"
    if not path.is_file():
        return None
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        log.warning("cannot read %s: %s", path, exc)
        return None
    return pathspec.GitIgnoreSpec.from_lines(lines)


def _ignored(specs: list[tuple[str, pathspec.GitIgnoreSpec]], rel: str, is_dir: bool) -> bool:
    """Deepest matching .gitignore wins; within one file, the last match wins."""
    verdict = False
    for base, spec in specs:
        sub = rel[len(base) + 1:] if base else rel
        result = spec.check_file(sub + "/" if is_dir else sub)
        if result.include is not None:
            verdict = result.include
    return verdict


def discover(root: str | os.PathLike, extensions: tuple[str, ...]) -> list[str]:
    """Project-relative POSIX paths of every file to scan, sorted."""
    root = Path(root).resolve()
    found: list[str] = []
    # (relative dir, spec) for each .gitignore on the path from the root.
    stack: list[tuple[str, pathspec.GitIgnoreSpec]] = []

    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        rel_dir = here.relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir

        # Drop specs from directories we have walked out of.
        stack = [(b, s) for b, s in stack if not b or rel_dir == b or rel_dir.startswith(b + "/")]
        spec = _load_gitignore(here)
        if spec is not None:
            stack.append((rel_dir, spec))

        keep = []
        for d in sorted(dirnames):
            full = here / d
            rel = f"{rel_dir}/{d}" if rel_dir else d
            if (d in SKIP_DIRS or d.endswith(".egg-info") or full.is_symlink()
                    or (full / "pyvenv.cfg").exists() or _ignored(stack, rel, True)):
                continue
            keep.append(d)
        dirnames[:] = keep

        for f in filenames:
            if not f.endswith(extensions):
                continue
            rel = f"{rel_dir}/{f}" if rel_dir else f
            if not _ignored(stack, rel, False):
                found.append(rel)
    return sorted(found)
