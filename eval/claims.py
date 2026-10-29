"""
eval/claims.py — reachability claims in the docs, computed from the results.

Every reachability number the docs state ("N marked, M wrong") is a record in
eval/claims.json: claim_id, the document and the run label it cites, the
dimension (reachable | unauthenticated), the numbers, and source_file, the
results file that holds that run. `compute(source_file)` recounts them from
the committed results, as eval/README.md "Reachability" defines it:

  over GitTrace's true positives on the four vulnerable targets, a true
  positive is *marked* when a finding matched to it has `reachable: true`
  (or `unauthenticated: true`), and marked *wrongly* when its ground-truth
  entry lists no route (or is not unauthenticated).

Two kinds of source file:
  results/<label>/summary.json   an eval run (run_eval.py); the run label is
                                 its `label`, the findings are in the
                                 per-target files next to it
  results/<name>.json            a reachability dump with a `run_label`
                                 (the graph-mode check); its findings are
                                 matched to the ground truth by rule category,
                                 file and line, as run_eval.score does

check() returns one problem per record whose label is not the label its
source records, whose numbers differ from that source, or whose wording is
missing from its document; unrecorded() one per count in the docs that no
record covers (or that uses the old wordings). tests/test_claims.py runs both.

    python eval/claims.py          # print every record against its source; exit 1 on a problem
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

EVAL = Path(__file__).resolve().parent
REPO = EVAL.parent
CLAIMS = EVAL / "claims.json"
TARGETS = ("vulpy-bad", "vulpy-good", "vulnerable-flask-app", "vulnpy")
DIMENSIONS = ("reachable", "unauthenticated")


def wording(label: str, marked: int, wrong: int) -> str:
    """The one wording every document uses for a claim."""
    return f"`{label}`: {marked} marked, {wrong} wrong"


def _truth(target: str) -> dict[str, dict]:
    data = json.loads((EVAL / target / "ground_truth.json").read_text(encoding="utf-8"))
    return {v["id"]: v for v in data["vulnerabilities"]}


def _right(vuln: dict, dimension: str) -> bool:
    reach = vuln.get("reachable") or {}
    return bool(reach.get("routes")) if dimension == "reachable" else bool(reach.get("unauthenticated"))


def _categories() -> dict[str, str]:
    sys.path.insert(0, str(REPO))
    from gittrace.languages import plugins
    return {r.rule_id: r.category for p in plugins() for r in p.rules()}


def _matches(vulns: dict[str, dict], category: str, file: str, line: int) -> str | None:
    return next((vid for vid, v in vulns.items()
                 if v["category"] == category and v["file"] == file and line in v["lines"]), None)


def source_label(source_file: str) -> str | None:
    """The run label a results file records (None when it records none)."""
    data = json.loads((REPO / source_file).read_text(encoding="utf-8"))
    return data.get("label") if Path(source_file).name == "summary.json" else data.get("run_label")


def compute(source_file: str) -> dict[str, tuple[int, int]]:
    """{dimension: (marked, wrong)} over the four vulnerable targets."""
    path = REPO / source_file
    counts = {d: [0, 0] for d in DIMENSIONS}
    if path.name == "summary.json":                     # an eval run: results/<label>/<target>.json
        for target in TARGETS:
            run = json.loads((path.parent / f"{target}.json").read_text(encoding="utf-8"))
            vulns = _truth(target)
            by_id = {f["id"]: f for f in run["gittrace_findings"]}
            for vid, ids in run["gittrace"]["true_positives"].items():
                for d in DIMENSIONS:
                    if any(by_id[i][d] for i in ids):
                        counts[d][0] += 1
                        counts[d][1] += not _right(vulns[vid], d)
    else:                                               # a reachability dump
        data = json.loads(path.read_text(encoding="utf-8"))
        category = _categories()
        for target in TARGETS:
            vulns = _truth(target)
            hits: dict[str, dict[str, bool]] = {}
            for f in data["targets"][target]["findings"]:
                file, line, _ = f["id"].rsplit("::", 2)
                vid = _matches(vulns, category[f["rule_id"]], file, int(line))
                if vid is not None:
                    seen = hits.setdefault(vid, {d: False for d in DIMENSIONS})
                    for d in DIMENSIONS:
                        seen[d] = seen[d] or bool(f[d])
            for vid, seen in hits.items():
                for d in DIMENSIONS:
                    if seen[d]:
                        counts[d][0] += 1
                        counts[d][1] += not _right(vulns[vid], d)
    return {d: (m, w) for d, (m, w) in counts.items()}


def load(path: Path = CLAIMS) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))["claims"]


def check(claims: list[dict]) -> list[str]:
    problems = []
    for c in claims:
        recorded = source_label(c["source_file"])
        if recorded != c["label"]:
            problems.append(f"{c['claim_id']}: label {c['label']!r}, but {c['source_file']} records {recorded!r}")
            continue
        marked, wrong = compute(c["source_file"])[c["dimension"]]
        if (c["marked"], c["wrong"]) != (marked, wrong):
            problems.append(f"{c['claim_id']}: {c['marked']} marked, {c['wrong']} wrong, but "
                            f"{c['source_file']} gives {marked} marked, {wrong} wrong ({c['dimension']})")
            continue
        text = (REPO / c["doc"]).read_text(encoding="utf-8")
        if wording(c["label"], c["marked"], c["wrong"]) not in " ".join(text.split()):
            problems.append(f"{c['claim_id']}: {c['doc']} does not say "
                            f"{wording(c['label'], c['marked'], c['wrong'])!r}")
    return problems


DOCS = ("README.md", "RELEASE_NOTES_2.0.0.md", "CHANGELOG.md", "eval/README.md", "scripts/demo.md")
_STATED = re.compile(r"`([\w-]+)`\**: (\d+) marked, (\d+) wrong")
_ANY = re.compile(r"\b\d+ marked, \d+ wrong")
# The reachability wordings used before claims.json: a count stated this way has no record.
_LEGACY = re.compile(r"\b\d+,? and \d+ wrongly\b|\b\d+ wrongly\b|\d+ \(\d+ / \d+\)|\bmarks \*\*\d+, and")


def unrecorded(claims: list[dict], docs: tuple[str, ...] = DOCS) -> list[str]:
    """Counts in the docs that no record covers: a labelled "N marked, M wrong"
    without a record, an unlabelled one, or one in the old wordings."""
    known = {(c["doc"], c["label"], c["marked"], c["wrong"]) for c in claims}
    problems = []
    for doc in docs:
        path = REPO / doc
        if not path.exists():
            continue
        text = " ".join(path.read_text(encoding="utf-8").split())
        stated = _STATED.findall(text)
        for label, marked, wrong in stated:
            if (doc, label, int(marked), int(wrong)) not in known:
                problems.append(f"{doc}: {wording(label, int(marked), int(wrong))!r} has no record in claims.json")
        if len(_ANY.findall(text)) != len(stated):
            problems.append(f"{doc}: a count \"N marked, M wrong\" without a run label")
        for m in _LEGACY.finditer(text):
            problems.append(f"{doc}: {m.group(0)!r} is a count in the old wording, with no record")
    return problems


def main() -> int:
    claims = load()
    for c in claims:
        got = compute(c["source_file"])[c["dimension"]]
        print(f"{c['claim_id']:<34} {c['doc']:<24} {c['dimension']:<16} "
              f"{wording(c['label'], c['marked'], c['wrong'])}  source: {got[0]} marked, {got[1]} wrong")
    problems = check(claims) + unrecorded(claims)
    for p in problems:
        print("PROBLEM:", p)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
