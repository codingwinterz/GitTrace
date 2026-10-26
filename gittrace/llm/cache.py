"""
gittrace.llm.cache — model replies on disk, so a rescan does not ask again.

    <project>/.gittrace/cache/<key[:2]>/<key>.json

The key is a sha256 over the task, the model name, PROMPT_VERSION and the
sha256 of the full prompt. The prompt carries the source the model saw (the
flagged lines, the function, its callers, the attack paths), so any change
to that code, a different model or a new prompt version misses the cache.

Only validated replies are stored, and an entry is validated again when read:
an entry that no longer matches the schema is reported and asked for again,
never used. `.gittrace/` gets a `.gitignore` of `*` (as pytest does for its
cache) so it never shows up in the project's git status, and discovery
skips it.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
from pathlib import Path

log = logging.getLogger(__name__)

CACHE_DIR = Path(".gittrace") / "cache"


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def cache_key(task: str, model: str, prompt_version: str, prompt: str) -> str:
    return sha256(json.dumps({"task": task, "model": model, "prompt_version": prompt_version,
                              "prompt_sha256": sha256(prompt)}, sort_keys=True))


class Cache:
    def __init__(self, project_root: str | os.PathLike):
        self.base = Path(project_root) / ".gittrace"
        self.directory = Path(project_root) / CACHE_DIR
        self.hits = 0
        self.misses = 0

    def _path(self, key: str) -> Path:
        return self.directory / key[:2] / f"{key}.json"

    def get(self, key: str) -> dict | None:
        path = self._path(key)
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            self.misses += 1
            return None
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("ignoring unreadable cache entry %s: %s", path, exc)
            self.misses += 1
            return None
        if not isinstance(record, dict) or record.get("key") != key:
            log.warning("ignoring cache entry %s: it is not the entry for this key", path)
            self.misses += 1
            return None
        self.hits += 1
        return record

    def reject(self, key: str, problem: str) -> None:
        """A read entry failed validation: count it as a miss and drop it."""
        log.warning("cache entry %s failed validation (%s); asking the model again", key[:12], problem)
        self.hits -= 1
        self.misses += 1
        try:
            self._path(key).unlink()
        except OSError:
            pass

    def put(self, key: str, record: dict) -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        ignore = self.base / ".gitignore"
        if not ignore.exists():
            ignore.write_text("# created by gittrace: model reply cache\n*\n", encoding="utf-8")
        fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump({**record, "key": key}, fh, indent=1)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
