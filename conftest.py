"""
conftest.py — test bootstrap.

`utils.py` reads the FalkorDB connection settings at import time, so importing
`app` on a machine without a `.env` raises RuntimeError before pytest can collect
a single test. The offline suite never dials the database (every graph call is
mocked), so placeholder settings are enough to let collection succeed.

These defaults are only applied when there is no `.env` to load and no real
settings in the environment, which keeps `test_integration.py` pointed at the
configured instance on a developer machine.
"""

from __future__ import annotations

import os
from pathlib import Path

_HAS_DOTENV = (Path(__file__).resolve().parent / ".env").exists()

if not _HAS_DOTENV:
    os.environ.setdefault("FALKORDB_HOST", "localhost")
    os.environ.setdefault("FALKORDB_PORT", "6379")
    os.environ.setdefault("FALKORDB_USER", "default")
    os.environ.setdefault("FALKORDB_PASSWORD", "")
