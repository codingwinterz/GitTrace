"""
Raw secret values must never appear in eval output (eval/hygiene.py).

The committed results are checked against eval/secret_values.sha256, so this
runs in CI without the target checkouts. In Phase 5 a review reason copied
mealie's default admin password into six triage result files; these tests
fail if that, or anything like it, comes back.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

EVAL = Path(__file__).resolve().parent.parent / "eval"
sys.path.insert(0, str(EVAL))

import hygiene  # noqa: E402

# Made-up values, so this file does not list a real one.
STRONG, WORD = "Tr0ub4dor&3x", "hunter"
HASHES = frozenset({hygiene.sha256(STRONG), hygiene.sha256(WORD)})


def test_committed_eval_results_hold_no_raw_secret():
    leaks = hygiene.find_leaks(hygiene.RESULTS)
    assert leaks == [], "raw secret values in eval/results; run `python eval/hygiene.py --scrub`:\n" + \
        "\n".join(f"{f}:{n}: {v}" for f, n, v in leaks)


def test_review_files_hold_no_raw_secret():
    """Review reasons are copied into the triage results as the label source."""
    reviews = sorted(EVAL.glob("*/review.json"))
    assert reviews
    for review in reviews:
        assert hygiene.file_leaks(review) == []


def test_hash_list_is_populated():
    # 29 values when the list was first built from the pinned targets; it only grows.
    assert len(hygiene.known_hashes()) >= 29


@pytest.mark.parametrize("text", [
    f"review: default admin password '{STRONG}' shipped in code",
    f'detail: "app.config[\'SECRET_KEY\'] = \\"{STRONG}\\""',
    f"PASSWORD={STRONG} in the environment file",
    f"admin_password = '{WORD}' is used only when auth is off",
    f"default Postgres password '{WORD}' in code",
])
def test_leak_is_found_and_scrubbed(text):
    assert list(hygiene.leaks_in(text, HASHES))
    clean = hygiene.scrub(text, HASHES)
    assert STRONG not in clean and f"'{WORD}'" not in clean
    assert list(hygiene.leaks_in(clean, HASHES)) == []


@pytest.mark.parametrize("text", [
    f"user.username = '{WORD}'",              # a plain word, not after a secret word
    f'the "{WORD}" target',
    f"value '{hygiene.mask(STRONG)}' is masked",
    "nothing quoted here",
])
def test_ordinary_text_is_not_a_leak(text):
    assert list(hygiene.leaks_in(text, HASHES)) == []
    assert hygiene.scrub(text, HASHES) == text


def test_planted_leak_in_a_json_result_is_caught(tmp_path):
    """JSON is checked after decoding, so escaped quotes do not hide a value."""
    record = {"records": [{"source": f"review: default admin password '{STRONG}'",
                           "fix_diff": f"-API_KEY = \"{STRONG}\"\n+API_KEY = os.environ['API_KEY']"}]}
    out = tmp_path / "run.json"
    out.write_text(json.dumps(record, indent=2), encoding="utf-8")
    assert len(hygiene.find_leaks(tmp_path, HASHES)) == 2
    out.write_text(json.dumps(hygiene.scrub_obj(record, HASHES), indent=2), encoding="utf-8")
    assert hygiene.find_leaks(tmp_path, HASHES) == []
    assert STRONG not in out.read_text(encoding="utf-8")


def test_ground_truth_values_cover_secrets_the_rule_misses():
    truth = {"vulnerabilities": [
        {"category": "hardcoded-secret", "detail": f"app.config['SECRET_KEY_HMAC'] = '{STRONG}' (signs JWTs)"},
        {"category": "hardcoded-secret", "detail": "key = 'JHtM1wEt...' (truncated in the label)"},
        {"category": "sql-injection", "detail": "query = 'SELECT 1'"},
    ]}
    assert hygiene.ground_truth_values(truth) == {STRONG}
