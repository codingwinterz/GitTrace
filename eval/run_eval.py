"""
eval/run_eval.py — reproduce the GitTrace evaluation (see eval/README.md).

    python eval/run_eval.py                       # results in eval/results/untouched/
    python eval/run_eval.py --label after-tuning  # a second, separately labelled run
    python eval/run_eval.py --graph               # use FalkorDB instead of --offline

For each pinned target (eval/targets.json) this checks out the commit under
eval/.src/, runs `gittrace scan` and Bandit, and for the vulnerable apps matches
both tools' findings against eval/<target>/ground_truth.json. For the real-world
projects it counts findings and, when eval/<target>/review.json exists, computes
the reviewed false-positive rate. The checked-out code is only read, never run.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path

EVAL = Path(__file__).resolve().parent
REPO = EVAL.parent
SRC = EVAL / ".src"
BANDIT_VENV = EVAL / ".bandit-venv"
BANDIT_VERSION = "1.9.4"

CATEGORY_BY_BANDIT = {
    "B608": "sql-injection", "B610": "sql-injection", "B611": "sql-injection",
    "B102": "code-injection", "B307": "code-injection",
    "B602": "command-injection", "B604": "command-injection", "B605": "command-injection",
    "B301": "unsafe-deserialization", "B302": "unsafe-deserialization",
    "B506": "unsafe-deserialization",
    "B105": "hardcoded-secret", "B106": "hardcoded-secret", "B107": "hardcoded-secret",
}


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", **kw)


def checkout(target: dict) -> Path:
    """Fetch exactly the pinned commit into eval/.src/<repo name>."""
    repo_dir = SRC / target["repo"].rstrip("/").rsplit("/", 1)[-1]
    if not (repo_dir / ".git").exists():
        repo_dir.mkdir(parents=True, exist_ok=True)
        _run(["git", "-C", str(repo_dir), "init", "-q"], check=True)
        _run(["git", "-C", str(repo_dir), "remote", "add", "origin", target["repo"]], check=True)
    head = _run(["git", "-C", str(repo_dir), "rev-parse", "HEAD"]).stdout.strip()
    if head != target["commit"]:
        has = _run(["git", "-C", str(repo_dir), "cat-file", "-e", target["commit"] + "^{commit}"])
        if has.returncode != 0:
            _run(["git", "-C", str(repo_dir), "fetch", "-q", "--depth", "1", "origin", target["commit"]],
                 check=True)
        _run(["git", "-C", str(repo_dir), "checkout", "-q", "--detach", target["commit"]], check=True)
    return repo_dir / target["scan_path"]


def bandit() -> Path:
    exe = BANDIT_VENV / ("Scripts/bandit.exe" if os.name == "nt" else "bin/bandit")
    if not exe.exists():
        _run([sys.executable, "-m", "venv", str(BANDIT_VENV)], check=True)
        py = BANDIT_VENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        _run([str(py), "-m", "pip", "install", "-q", f"bandit=={BANDIT_VERSION}"], check=True)
    return exe


def run_gittrace(path: Path, use_graph: bool) -> dict:
    cmd = [sys.executable, "-m", "gittrace", "scan", str(path), "--no-blame",
           "--format", "json", "--fail-on", "none"]
    if not use_graph:
        cmd.append("--offline")
    out = _run(cmd, cwd=REPO, env={**os.environ, "PYTHONPATH": str(REPO)})
    if out.returncode != 0:
        raise RuntimeError(f"gittrace scan failed on {path}:\n{out.stderr}")
    return json.loads(out.stdout)


def run_bandit(path: Path) -> dict:
    out = _run([str(bandit()), "-r", str(path), "-f", "json", "-q"])
    if out.returncode not in (0, 1):            # 1 = issues found
        raise RuntimeError(f"bandit failed on {path}:\n{out.stderr}")
    return json.loads(out.stdout)


def _rel(path: str, root: Path) -> str:
    p = Path(path)
    if not p.is_absolute():
        p = (Path.cwd() / p)
    return p.resolve().relative_to(root.resolve()).as_posix()


def gittrace_findings(data: dict) -> list[dict]:
    return [{
        "tool": "gittrace", "id": f["id"], "rule": f["rule_id"], "category": f["category"],
        "file": f["location"]["file"],
        "lines": list(range(f["location"]["line"], f["location"]["end_line"] + 1)),
        "severity": f["severity"], "score": f["score"],
        "reachable": f["reachability"]["reachable"],
        "unauthenticated": f["reachability"]["unauthenticated"],
        "snippet": f["snippet"].strip().splitlines()[0][:160] if f["snippet"] else "",
    } for f in data["findings"]]


def bandit_findings(data: dict, root: Path) -> list[dict]:
    out = []
    for r in data["results"]:
        category = CATEGORY_BY_BANDIT.get(r["test_id"])
        if category is None:
            continue
        file = _rel(r["filename"], root)
        out.append({
            "tool": "bandit", "id": f"{file}:{r['line_number']}:{r['test_id']}",
            "rule": r["test_id"], "category": category, "file": file,
            "lines": r.get("line_range") or [r["line_number"]],
            "severity": r["issue_severity"].lower(),
            "snippet": r["code"].strip().splitlines()[0][:160] if r.get("code") else "",
        })
    return out


def score(findings: list[dict], truth: dict) -> dict:
    """Match findings to ground truth by category, file and an overlapping line."""
    vulns = truth["vulnerabilities"]
    matched: dict[str, list[str]] = {}
    fps, fp_benign, duplicates = [], [], []
    for f in findings:
        hit = next((v for v in vulns if v["category"] == f["category"] and v["file"] == f["file"]
                    and set(v["lines"]) & set(f["lines"])), None)
        if hit is not None:
            (duplicates if hit["id"] in matched else []).append(f["id"])
            matched.setdefault(hit["id"], []).append(f["id"])
            continue
        benign = next((b for b in truth.get("benign", []) if b["category"] == f["category"]
                       and b["file"] == f["file"] and set(b["lines"]) & set(f["lines"])), None)
        (fp_benign if benign is not None else fps).append(f)
    tp = len(matched)
    fp = len(fps) + len(fp_benign)
    fn = [v for v in vulns if v["id"] not in matched]
    by_id = {f["id"]: f for f in findings}
    result = {
        "ground_truth": len(vulns),
        "tp": tp, "fp": fp, "fp_benign": len(fp_benign), "fn": len(fn),
        "duplicates": len(duplicates),
        "precision": round(tp / (tp + fp), 3) if tp + fp else None,
        "precision_ignoring_benign": round(tp / (tp + len(fps)), 3) if tp + len(fps) else None,
        "recall": round(tp / len(vulns), 3) if vulns else None,
        "true_positives": {vid: ids for vid, ids in sorted(matched.items())},
        "false_positives": fps,
        "false_positives_benign": fp_benign,
        "false_negatives": [{"id": v["id"], "category": v["category"], "file": v["file"],
                             "lines": v["lines"], "detail": v["detail"]} for v in fn],
    }
    if findings and findings[0]["tool"] == "gittrace":
        result["tp_reachable_unauthenticated"] = sum(
            1 for ids in matched.values() if any(by_id[i]["unauthenticated"] for i in ids))
        result["tp_reachable_any"] = sum(
            1 for ids in matched.values() if any(by_id[i]["reachable"] for i in ids))
    return result


def evaluate(label: str, use_graph: bool) -> dict:
    targets = json.loads((EVAL / "targets.json").read_text(encoding="utf-8"))
    out_dir = EVAL / "results" / label
    out_dir.mkdir(parents=True, exist_ok=True)
    summary: dict = {"label": label, "bandit_version": BANDIT_VERSION,
                     "gittrace_mode": "graph" if use_graph else "offline",
                     "vulnerable": {}, "real_world": {}}

    for t in targets["vulnerable"]:
        path = checkout(t)
        truth = json.loads((EVAL / t["name"] / "ground_truth.json").read_text(encoding="utf-8"))
        g = gittrace_findings(run_gittrace(path, use_graph))
        b = bandit_findings(run_bandit(path), path)
        record = {"target": t, "gittrace_findings": g, "bandit_findings": b,
                  "gittrace": score(g, truth), "bandit": score(b, truth),
                  "ground_truth_reachable_unauthenticated": sum(
                      1 for v in truth["vulnerabilities"]
                      if (v.get("reachable") or {}).get("unauthenticated"))}
        (out_dir / f"{t['name']}.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
        summary["vulnerable"][t["name"]] = {k: {m: record[k][m] for m in (
            "ground_truth", "tp", "fp", "fp_benign", "fn", "precision", "precision_ignoring_benign",
            "recall", "tp_reachable_unauthenticated", "tp_reachable_any") if m in record[k]}
            for k in ("gittrace", "bandit")}
        summary["vulnerable"][t["name"]]["ground_truth_reachable_unauthenticated"] = \
            record["ground_truth_reachable_unauthenticated"]

    for tool in ("gittrace", "bandit"):
        rows = [v[tool] for v in summary["vulnerable"].values()]
        tp, fp, fn = (sum(r[k] for r in rows) for k in ("tp", "fp", "fn"))
        benign = sum(r["fp_benign"] for r in rows)
        total = {"ground_truth": tp + fn, "tp": tp, "fp": fp, "fp_benign": benign, "fn": fn,
                 "precision": round(tp / (tp + fp), 3) if tp + fp else None,
                 "precision_ignoring_benign": round(tp / (tp + fp - benign), 3) if tp + fp - benign else None,
                 "recall": round(tp / (tp + fn), 3) if tp + fn else None}
        if tool == "gittrace":
            total["tp_reachable_unauthenticated"] = sum(r["tp_reachable_unauthenticated"] for r in rows)
            total["tp_reachable_any"] = sum(r["tp_reachable_any"] for r in rows)
        summary.setdefault("overall", {})[tool] = total

    for t in targets["real_world"]:
        path = checkout(t)
        data = run_gittrace(path, use_graph)
        g = gittrace_findings(data)
        b = bandit_findings(run_bandit(path), path)
        review_file = EVAL / t["name"] / "review.json"
        entry = {"target": t, "scanned": data["scanned"], "gittrace_findings": len(g),
                 "by_rule": dict(Counter(f["rule"] for f in g)),
                 "by_severity": dict(Counter(f["severity"] for f in g)),
                 "reachable": sum(1 for f in g if f["reachable"]),
                 "unauthenticated": sum(1 for f in g if f["unauthenticated"]),
                 "bandit_findings_same_categories": len(b),
                 "bandit_by_category": dict(Counter(f["category"] for f in b))}
        if review_file.exists():
            review = json.loads(review_file.read_text(encoding="utf-8"))["verdicts"]
            missing = sorted({f["id"] for f in g} - set(review))
            fp = sum(1 for f in g if review.get(f["id"], {}).get("verdict") == "fp")
            entry.update({"reviewed": len(g) - len(missing), "unreviewed": missing,
                          "false_positives": fp,
                          "false_positive_rate": round(fp / (len(g) - len(missing)), 3)
                          if len(g) > len(missing) else None})
        else:
            template = {"verdicts": {f["id"]: {"verdict": "tp|fp", "reason": "", "finding": f}
                                     for f in g}}
            (EVAL / t["name"]).mkdir(exist_ok=True)
            (EVAL / t["name"] / "review_template.json").write_text(json.dumps(template, indent=2),
                                                                   encoding="utf-8")
        (out_dir / f"{t['name']}.json").write_text(json.dumps({**entry, "findings": g}, indent=2),
                                                   encoding="utf-8")
        summary["real_world"][t["name"]] = entry

    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (out_dir / "summary.md").write_text(markdown(summary), encoding="utf-8")
    return summary


def _pct(x) -> str:
    return "–" if x is None else f"{x:.0%}"


def markdown(s: dict) -> str:
    lines = [f"# Evaluation results ({s['label']})", "",
             f"GitTrace `scan --{s['gittrace_mode']}`; Bandit {s['bandit_version']}, its findings in the "
             "same five categories only.", "",
             "| Target | Tool | Ground truth | TP | FP (of which benign) | FN | Precision | Recall | "
             "TP reachable without auth |",
             "|---|---|---|---|---|---|---|---|---|"]
    for name, row in list(s["vulnerable"].items()) + [("**overall**", s["overall"])]:
        for tool in ("gittrace", "bandit"):
            r = row[tool]
            reach = str(r["tp_reachable_unauthenticated"]) if tool == "gittrace" else "n/a"
            lines.append(f"| {name} | {tool} | {r['ground_truth']} | {r['tp']} | {r['fp']} ({r['fp_benign']}) | "
                         f"{r['fn']} | {_pct(r['precision'])} | {_pct(r['recall'])} | {reach} |")
    lines += ["", "Real-world projects (GitTrace):", "",
              "| Project | Files | Endpoints | Findings | Reachable | Unauthenticated | Reviewed FP rate | "
              "Bandit (same categories) |",
              "|---|---|---|---|---|---|---|---|"]
    for name, r in s["real_world"].items():
        fp_rate = (f"{r['false_positives']}/{r['reviewed']} ({_pct(r['false_positive_rate'])})"
                   if "reviewed" in r else "not reviewed")
        lines.append(f"| {name} | {r['scanned']['files']} | {r['scanned']['endpoints']} | "
                     f"{r['gittrace_findings']} | {r['reachable']} | {r['unauthenticated']} | {fp_rate} | "
                     f"{r['bandit_findings_same_categories']} |")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--label", default="untouched")
    parser.add_argument("--graph", action="store_true", help="run gittrace against FalkorDB")
    args = parser.parse_args()
    summary = evaluate(args.label, args.graph)
    sys.stdout.write(markdown(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
