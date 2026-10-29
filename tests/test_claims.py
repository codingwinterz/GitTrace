"""
tests/test_claims.py — the reachability claims in the docs agree with the results.

eval/claims.json holds one record per claim (claim_id, doc, run label,
dimension, marked, wrong, source_file); eval/claims.py recounts each from the
committed results file it names. This fails when a claim's label is not the
run label its source records, when its numbers differ from that source, when
its "`label`: N marked, M wrong" wording is missing from its document, or when
a document states a count that no record covers.

Run:  pytest tests/test_claims.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

EVAL = Path(__file__).resolve().parent.parent / "eval"
sys.path.insert(0, str(EVAL))

import claims  # noqa: E402

UNTOUCHED = "eval/results/untouched/summary.json"
LATER = "eval/results/after-reachability/summary.json"


def _record(**changes) -> dict:
    base = {"claim_id": "fixture", "doc": "README.md", "label": "untouched",
            "dimension": "unauthenticated", "marked": 7, "wrong": 1, "source_file": UNTOUCHED}
    return {**base, **changes}


def test_every_claim_matches_its_source_run():
    assert claims.check(claims.load()) == []


def test_no_count_in_the_docs_is_unrecorded():
    assert claims.unrecorded(claims.load()) == []


def test_the_two_runs_the_docs_compare():
    # The untouched run marked VF-1 (POST /search) reachable without auth wrongly;
    # after-reachability counts the JWT check in its body. Reachability itself is 7 / 0 in both.
    assert claims.source_label(UNTOUCHED) == "untouched"
    assert claims.compute(UNTOUCHED) == {"reachable": (7, 0), "unauthenticated": (7, 1)}
    assert claims.source_label(LATER) == "after-reachability"
    assert claims.compute(LATER) == {"reachable": (7, 0), "unauthenticated": (6, 0)}


def test_a_mislabelled_claim_fails():
    # The untouched numbers, labelled as the later run: the source records "untouched".
    (problem,) = claims.check([_record(label="after-reachability")])
    assert "label 'after-reachability'" in problem and "records 'untouched'" in problem


def test_the_later_label_with_the_baseline_numbers_fails():
    (problem,) = claims.check([_record(label="after-reachability", source_file=LATER)])
    assert "7 marked, 1 wrong" in problem and "gives 6 marked, 0 wrong" in problem


def test_wrong_numbers_fail():
    (problem,) = claims.check([_record(wrong=0)])
    assert "gives 7 marked, 1 wrong" in problem


def test_a_source_without_a_run_label_cannot_be_cited():
    (problem,) = claims.check([_record(label="after-reachability-port",
                                       source_file="eval/results/after_reachability_port.json")])
    assert "records None" in problem


def test_a_claim_missing_from_its_document_fails(tmp_path):
    doc = tmp_path / "doc.md"
    doc.write_text("Marked reachable without auth: `untouched`: 7 marked, 0 wrong.\n", encoding="utf-8")
    (problem,) = claims.check([_record(doc=str(doc))])
    assert "does not say '`untouched`: 7 marked, 1 wrong'" in problem


def test_unrecorded_and_old_wordings_are_caught(tmp_path):
    doc = tmp_path / "tour.md"
    doc.write_text(
        "GitTrace marks **7, and 0 wrongly**.\n"                     # the old README sentence
        "| Marked reachable (correctly / wrongly) | 7 (7 / 0) |\n"   # the old eval/README cell
        "`untouched`: 7 marked, 0 wrong\n"                           # labelled, but no record
        "7 marked, 1 wrong\n",                                       # no run label at all
        encoding="utf-8")
    problems = claims.unrecorded([], docs=(str(doc),))
    assert any("has no record" in p for p in problems)
    assert any("without a run label" in p for p in problems)
    # The old README sentence trips two patterns ("marks **7, and", "0 wrongly"), the cell one.
    assert sum("old wording" in p for p in problems) == 3
