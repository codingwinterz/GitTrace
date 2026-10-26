"""
test_llm_live.py — one real triage against a local Ollama.

Skipped unless Ollama answers at $OLLAMA_API_BASE (default
http://localhost:11434) and has the model pulled ($GITTRACE_MODEL, default
ollama/llama3.1:8b). Not run in CI. It checks the plumbing (LiteLLM,
num_ctx, the JSON schema, validation, the fix check), not the model's
judgement, which eval/run_triage.py measures.

Run:  pytest tests/test_llm_live.py -v
"""

from __future__ import annotations

import json
import os
import shutil
import urllib.request

import pytest

import expected_sample_app
from gittrace.core.scan import scan
from gittrace.llm.client import ModelClient, resolve_model
from gittrace.llm.schemas import MAX_ADJUSTMENT, MIN_ADJUSTMENT, VERDICTS
from gittrace.llm.triage import Triager

MODEL = resolve_model(None)
BASE = os.environ.get("OLLAMA_API_BASE", "http://localhost:11434").rstrip("/")


def _pulled() -> set[str]:
    try:
        with urllib.request.urlopen(f"{BASE}/api/tags", timeout=3) as resp:
            return {m["name"] for m in json.load(resp)["models"]}
    except (OSError, ValueError, KeyError):
        return set()


pytestmark = [
    pytest.mark.skipif(not MODEL.startswith("ollama/"), reason=f"{MODEL} is not an Ollama model"),
    pytest.mark.skipif(MODEL.split("/", 1)[-1] not in _pulled(),
                       reason=f"Ollama is not running at {BASE} or {MODEL} is not pulled"),
]


def test_real_triage_of_a_sql_injection(tmp_path):
    root = shutil.copytree(expected_sample_app.ROOT, tmp_path / "sample_app",
                           ignore=shutil.ignore_patterns(".gittrace", "__pycache__"))
    result = scan(root, offline=True, blame=False)
    finding = next(f for f in result.findings if f.id == "app/db.py::17::9")
    t = Triager(result.analysis, ModelClient(MODEL)).triage(finding)
    assert t.error is None, t.error
    assert t.verdict in VERDICTS
    assert MIN_ADJUSTMENT <= t.adjustment <= MAX_ADJUSTMENT
    assert t.adjusted_score == finding.score + t.adjustment
    assert t.reason and len(t.reason) <= 500
    assert 1 <= t.attempts <= 2 and t.seconds > 0
    if t.fix is not None and t.fix.valid:
        assert t.fix.diff.startswith("--- a/app/db.py\n+++ b/app/db.py\n")
    assert (root / "app" / "db.py").read_bytes() == \
        (expected_sample_app.ROOT / "app" / "db.py").read_bytes()      # never applied
