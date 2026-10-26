"""
gittrace.config — where GitTrace's settings come from.

Environment variables always win. Below them, the first of these `.env` files
that exists fills in what is not set:

  1. $GITTRACE_ENV_FILE
  2. `.env` at the root of a source checkout (next to pyproject.toml)
  3. `.env` in the user's config directory (platformdirs: e.g.
     ~/.config/gittrace/.env, %LOCALAPPDATA%\\gittrace\\.env)

The current directory is never read: it is usually the project being
scanned, and its `.env` must not configure GitTrace (or hand it that
project's secrets). With no file at all, the defaults apply: local Docker
FalkorDB, local Ollama models.
"""

from __future__ import annotations

import os
from pathlib import Path

ENV_FILE_VAR = "GITTRACE_ENV_FILE"
_loaded: Path | None = None
_done = False


def candidates() -> list[Path]:
    files = []
    if os.environ.get(ENV_FILE_VAR, "").strip():
        files.append(Path(os.environ[ENV_FILE_VAR].strip()).expanduser())
    checkout = Path(__file__).resolve().parents[1]
    if (checkout / "pyproject.toml").is_file():
        files.append(checkout / ".env")
    try:
        from platformdirs import user_config_dir
        files.append(Path(user_config_dir("gittrace", appauthor=False)) / ".env")
    except ImportError:
        pass
    return files


def load() -> Path | None:
    """Load the first `.env` that exists (once); returns it, or None for defaults."""
    global _loaded, _done
    if not _done:
        from dotenv import load_dotenv

        _done = True
        for path in candidates():
            if path.is_file():
                load_dotenv(path, override=False)
                _loaded = path
                break
    return _loaded
