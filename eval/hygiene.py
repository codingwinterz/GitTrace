"""
eval/hygiene.py — keep raw secret values out of eval output.

GitTrace masks hardcoded secrets in every report, but eval output also
carries text written by people (ground-truth `detail`, review `reason`) and
by the model. Any of those can quote a secret verbatim; in Phase 5 a review
reason copied mealie's default password into six triage result files.

The values to keep out are listed by hash in eval/secret_values.sha256, so
the check runs without the target checkouts (in CI) and the repository holds
no raw value. They are collected from the checkouts by running the hardcoded
secret rule (GT-SECRET-001) over every target, plus every value a ground truth
quotes for a hardcoded-secret entry (`... = 'value'`), which also covers
secrets the rule misses.

A candidate is any substring that sits between two equal quote characters on
one line, or the token after `=` or `:`. A candidate whose sha256 is listed is
a leak (a plain lower-case word only right after a secret word, see
`is_leak`); `scrub` replaces it with the rule's mask (first 3 characters kept).

    python eval/hygiene.py              # check eval/results; exit 1 on a leak
    python eval/hygiene.py --update     # add the values in the checkouts to the list
    python eval/hygiene.py --scrub      # mask leaks in eval/results in place
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

EVAL = Path(__file__).resolve().parent
REPO = EVAL.parent
RESULTS = EVAL / "results"
HASHES = EVAL / "secret_values.sha256"
sys.path.insert(0, str(REPO))

from gittrace.rules.hardcoded_secret import HardcodedSecret, mask  # noqa: E402

QUOTES = "'\"`"
MIN_LEN, MAX_LEN = 4, 200
_AFTER_ASSIGN = re.compile(r"""[=:]\s*([^\s'"`,;()\[\]{}]{%d,%d})""" % (MIN_LEN, MAX_LEN))
_GT_VALUE = re.compile(r"""=\s*(['"])(.+?)\1""")
_WORD = re.compile(r"^[a-z]+$")
_SECRET_BEFORE = re.compile(r"pass|pwd|secret|key|token", re.IGNORECASE)
CONTEXT = 24    # characters before a plain-word value searched for a secret word


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def known_hashes() -> frozenset[str]:
    if not HASHES.exists():
        return frozenset()
    return frozenset(line.strip() for line in HASHES.read_text(encoding="utf-8").splitlines()
                     if line.strip() and not line.startswith("#"))


def candidates(line: str):
    """(start, end) spans of the substrings that could be a quoted or assigned value."""
    for i, ch in enumerate(line):
        if ch not in QUOTES:
            continue
        j = line.find(ch, i + 1)
        while j != -1 and j - i - 1 <= MAX_LEN:
            if j - i - 1 >= MIN_LEN:
                yield i + 1, j
                if line[j - 1] == "\\":     # an escaped quote: \"value\"
                    yield i + 1, j - 1
            j = line.find(ch, j + 1)
    for m in _AFTER_ASSIGN.finditer(line):
        yield m.start(1), m.end(1)


def is_leak(line: str, start: int, end: int, hashes: frozenset[str]) -> bool:
    """A listed value. A plain lower-case word (`admin`, `secret`, `mealie`) is
    also an ordinary word, so it counts only right after a secret word
    (`password 'mealie'`, `SECRET_KEY'] = 'dvga'`), not in `username = 'admin'`."""
    value = line[start:end]
    if sha256(value) not in hashes:
        return False
    return not _WORD.match(value) or bool(_SECRET_BEFORE.search(line[max(0, start - CONTEXT):start]))


def leaks_in(text: str, hashes: frozenset[str]):
    """(line number, masked value) for each listed value in `text`."""
    for n, line in enumerate(text.split("\n"), 1):
        for start, end in candidates(line):
            if is_leak(line, start, end, hashes):
                yield n, mask(line[start:end])


def scrub(text: str, hashes: frozenset[str] | None = None) -> str:
    """`text` with every listed value masked."""
    hashes = known_hashes() if hashes is None else hashes
    out = []
    for line in text.split("\n"):
        spans = sorted({(s, e) for s, e in candidates(line) if is_leak(line, s, e, hashes)},
                       key=lambda se: (se[0], -se[1]))
        pos, parts = 0, []
        for s, e in spans:
            if s < pos:                     # inside a span already masked
                continue
            parts += [line[pos:s], mask(line[s:e])]
            pos = e
        out.append("".join(parts) + line[pos:])
    return "\n".join(out)


def scrub_obj(obj, hashes: frozenset[str] | None = None):
    """A JSON-like object with every string scrubbed (keys included)."""
    hashes = known_hashes() if hashes is None else hashes
    if isinstance(obj, str):
        return scrub(obj, hashes)
    if isinstance(obj, dict):
        return {scrub(k, hashes): scrub_obj(v, hashes) for k, v in obj.items()}
    if isinstance(obj, list):
        return [scrub_obj(v, hashes) for v in obj]
    return obj


def _strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)


def file_leaks(path: Path, hashes: frozenset[str] | None = None) -> list[tuple[str, int, str]]:
    """(file, line, masked value) for every listed value in one file. JSON is
    checked string by string after decoding (so `\\"` escapes do not hide a
    quote); the line number is then the string's index."""
    hashes = known_hashes() if hashes is None else hashes
    rel = (path.relative_to(REPO) if path.is_relative_to(REPO) else path).as_posix()
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []
    if path.suffix == ".json":
        return [(rel, i, v) for i, s in enumerate(_strings(json.loads(text))) for _, v in leaks_in(s, hashes)]
    return [(rel, n, v) for n, v in leaks_in(text, hashes)]


def find_leaks(root: Path = RESULTS, hashes: frozenset[str] | None = None) -> list[tuple[str, int, str]]:
    """file_leaks for every file under `root`."""
    hashes = known_hashes() if hashes is None else hashes
    return [leak for path in sorted(p for p in root.rglob("*") if p.is_file())
            for leak in file_leaks(path, hashes)]


def rule_values(analysis) -> set[str]:
    """The raw values GT-SECRET-001 flags in one analysed project."""
    rule = HardcodedSecret()
    return {a.value.value for a in analysis.assignments if rule.check_assignment(a) is not None}


def ground_truth_values(truth: dict) -> set[str]:
    out = set()
    for entry in truth.get("vulnerabilities", []) + truth.get("benign", []):
        if entry.get("category") == "hardcoded-secret" and entry.get("detail"):
            out |= {m.group(2) for m in _GT_VALUE.finditer(entry["detail"])
                    if not m.group(2).endswith("...") and len(m.group(2)) >= MIN_LEN}
    return out


def register(values) -> int:
    """Add values to the hash list; returns how many were new."""
    have = known_hashes()
    new = {sha256(v) for v in values if len(v) >= MIN_LEN} - have
    if new:
        lines = sorted(have | new)
        HASHES.write_text("# sha256 of secret values found in the eval targets (eval/hygiene.py)\n"
                          + "\n".join(lines) + "\n", encoding="utf-8")
    return len(new)


def target_values(name: str, analysis=None, path: Path | None = None) -> set[str]:
    """The secret values of one target: the rule's, from `analysis` (or a fresh
    analysis of `path`), and its ground truth's."""
    if analysis is None:
        from gittrace.core import pipeline
        analysis = pipeline.analyze(path)
    values = rule_values(analysis)
    truth = EVAL / name / "ground_truth.json"
    if truth.exists():
        values |= ground_truth_values(json.loads(truth.read_text(encoding="utf-8")))
    return values


def collect() -> set[str]:
    """Every secret value in the pinned eval targets (needs the checkouts)."""
    sys.path.insert(0, str(EVAL))
    import run_eval

    raw = json.loads((EVAL / "targets.json").read_text(encoding="utf-8"))
    targets = [t for g in (raw, raw["held_out"]) for k in ("vulnerable", "real_world") for t in g[k]]
    values: set[str] = set()
    for t in targets:
        values |= target_values(t["name"], path=run_eval.checkout(t))
    return values


def assert_clean(root: Path) -> None:
    """Stop an eval run whose output still holds a listed value."""
    leaks = find_leaks(root)
    if leaks:
        raise SystemExit("raw secret values in eval output:\n" + "\n".join(
            f"  {f}:{n}: {v}" for f, n, v in leaks))


def write_json(path: Path, obj) -> None:
    """Write eval output with every listed value masked."""
    path.write_text(json.dumps(scrub_obj(obj), indent=2), encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.write_text(scrub(text), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--update", action="store_true", help="add the checkouts' secret values to the list")
    parser.add_argument("--scrub", action="store_true", help="mask leaks in eval/results in place")
    args = parser.parse_args()
    if args.update:
        print(f"{register(collect())} new value(s); {len(known_hashes())} listed in {HASHES.name}")
    if args.scrub:
        for path in sorted({REPO / f for f, _, _ in find_leaks()}):
            if path.suffix == ".json":
                write_json(path, json.loads(path.read_text(encoding="utf-8")))
            else:
                write_text(path, path.read_text(encoding="utf-8"))
            print(f"scrubbed {path.relative_to(REPO).as_posix()}")
    leaks = find_leaks()
    for f, n, v in leaks:
        print(f"LEAK {f}:{n}: {v}")
    print(f"{len(leaks)} raw secret value(s) in eval/results ({len(known_hashes())} values listed)")
    return 1 if leaks else 0


if __name__ == "__main__":
    raise SystemExit(main())
