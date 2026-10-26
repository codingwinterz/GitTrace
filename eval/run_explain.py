"""
eval/run_explain.py — measure `gittrace explain` (see eval/README.md, "Explain").

    python eval/run_explain.py --draw-sample            # once, before any model run
    python eval/run_explain.py --label untouched        # both models, both targets, no cache
    python eval/run_explain.py --score untouched        # rating counts from the reviews

Targets (eval/explain/targets.json): tests/fixtures/sample_app and
miguelgrinberg/microblog at a pinned commit. Each run summarises what
`gittrace explain` summarises by default (every file, the project, the
important functions), with no cache, one model at a time, after one untimed
warm-up call, and records every summary with its seconds and its grounding
check.

Reviewed: every file summary and 30 function summaries drawn (seed 7) from
the important functions before any model ran: 10 from sample_app, 20 from
microblog. The reference notes in eval/explain/<target>/reference.json were
written before any summary existed; reviews (eval/explain/<target>/review.json)
rate each summary correct / partly correct / wrong, with a reason.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from collections import Counter
from pathlib import Path

EVAL = Path(__file__).resolve().parent
REPO = EVAL.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(EVAL))

import hygiene  # noqa: E402
import run_eval  # noqa: E402
import run_triage  # noqa: E402  (model info, GPU, code hash)

from gittrace.core import explain as facts  # noqa: E402
from gittrace.core.scan import scan  # noqa: E402
from gittrace.llm import explain as summaries  # noqa: E402
from gittrace.llm.client import ModelClient  # noqa: E402

MODELS = ("ollama/llama3.1:8b", "ollama/qwen2.5-coder:7b")
SAMPLE = EVAL / "explain" / "sample.json"
PER_TARGET = {"sample_app": 10, "microblog": 20}
RATINGS = ("correct", "partly", "wrong")


def _targets() -> dict[str, Path]:
    raw = json.loads((EVAL / "explain" / "targets.json").read_text(encoding="utf-8"))
    out = {}
    for name, t in raw.items():
        out[name] = (REPO / t["path"]) if "path" in t else run_eval.checkout(t)
    return out


def _power() -> str | None:
    """'AC' or 'battery' on a Windows laptop (timings on battery are slower)."""
    import subprocess
    try:
        out = subprocess.run(["powershell.exe", "-NoProfile", "-Command",
                              "(Get-CimInstance -Namespace root/wmi -ClassName BatteryStatus).PowerOnline"],
                             capture_output=True, text=True, timeout=20).stdout.strip().splitlines()
    except (OSError, subprocess.SubprocessError):
        return None
    return {"True": "AC", "False": "battery"}.get(out[0].strip()) if out else None


def _facts(path: Path):
    result = scan(path, offline=True, blame=False)
    return result, facts.build(result)


def draw_sample() -> dict:
    if SAMPLE.exists():
        raise SystemExit(f"{SAMPLE} exists: the sample is drawn once")
    rng = random.Random(7)
    out = {"seed": 7, "method": "random.sample of the important functions (default `explain`), "
                                "drawn before any model run", "targets": {}}
    for name, path in _targets().items():
        _, ex = _facts(path)
        important = sorted(f.id for f in ex.important())
        out["targets"][name] = {"important": len(important), "files": sorted(ex.files),
                                "sample": sorted(rng.sample(important, PER_TARGET[name]))}
    SAMPLE.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    return out


def run(label: str, models: list[str]) -> None:
    out_dir = EVAL / "results" / "explain" / label
    out_dir.mkdir(parents=True, exist_ok=True)
    targets = _targets()
    prepared = {name: _facts(path) for name, path in targets.items()}
    for name, (result, _) in prepared.items():
        hygiene.register(hygiene.target_values(name, result.analysis))
    summary = {"label": label, "prompt_version": summaries.EXPLAIN_VERSION,
               "llm_code_sha256": run_triage.code_sha256(), "gpu": run_triage._gpu(),
               "power_at_start": _power(), "models": {}}
    for model in models:
        client = ModelClient(model)
        name0, (result0, ex0) = next(iter(prepared.items()))
        warm = time.perf_counter()
        summaries.Explainer(ex0, result0.analysis, client).summarise("function", ex0.important()[0].id)
        warm = time.perf_counter() - warm
        per_target = {}
        for name, (result, ex) in prepared.items():
            explainer = summaries.Explainer(ex, result.analysis, client)        # no cache: timed
            plan = summaries.plan(ex, [f.id for f in ex.important()], list(ex.files), True)
            print(f"== {model} {name}: {len(plan)} calls", flush=True)
            run_ = explainer.execute(plan, lambda i, n, item: print(f"  {i}/{n} {item[0]} {item[1]}", flush=True))
            records = [s.to_dict() for s in run_.summaries.values()]
            per_target[name] = {"meta": run_.meta(), "records": records}
        slug = model.replace("/", "_").replace(":", "_")
        hygiene.write_json(out_dir / f"{slug}.json", {"model": run_triage._ollama_info(model),
                                                      "warmup_seconds": round(warm, 2), "targets": per_target})
        summary["models"][model] = {"warmup_seconds": round(warm, 2), "power_after": _power(),
                                    "targets": {n: _metrics(t["records"]) for n, t in per_target.items()}}
    hygiene.write_json(out_dir / "summary.json", summary)
    hygiene.write_text(out_dir / "summary.md", markdown(summary))
    hygiene.assert_clean(out_dir)
    sys.stdout.write(markdown(summary))


def _metrics(records: list[dict]) -> dict:
    def secs(level):
        xs = [r["seconds"] for r in records if r["level"] == level and r["error"] is None]
        return {"n": len(xs), "total": round(sum(xs), 1), "mean": round(sum(xs) / len(xs), 2) if xs else None,
                "max": round(max(xs), 2) if xs else None}
    return {
        "calls": len(records), "errors": sum(r["error"] is not None for r in records),
        "retried": sum(r["attempts"] > 1 for r in records),
        "context_cut": sum(bool(r["context_notes"]) for r in records),
        "mentions_kept": sum(len(r["grounding"]["kept"]) for r in records),
        "mentions_removed": sum(len(r["grounding"]["removed"]) for r in records),
        "summaries_with_removals": sum(bool(r["grounding"]["removed"]) for r in records),
        "seconds": {lvl: secs(lvl) for lvl in ("function", "file", "project")},
        "total_seconds": round(sum(r["seconds"] for r in records), 1),
    }


def markdown(summary: dict) -> str:
    lines = [f"# Explain results ({summary['label']})", "",
             f"Prompt `{summary['prompt_version']}` (gittrace/llm sha256 `{summary['llm_code_sha256'][:12]}`); "
             f"GPU: {summary['gpu']}; power at start: {summary.get('power_at_start')}; no cache.", "",
             "| Model | Target | Calls | Errors | Mentions kept / removed (summaries with removals) | "
             "s / function (mean, max) | s / file (mean) | s project | Total model s |",
             "|---|---|---|---|---|---|---|---|---|"]
    for model, m in summary["models"].items():
        for name, t in m["targets"].items():
            s = t["seconds"]
            lines.append(f"| {model} | {name} | {t['calls']} | {t['errors']} | {t['mentions_kept']} / "
                         f"{t['mentions_removed']} ({t['summaries_with_removals']}) | "
                         f"{s['function']['mean']}, {s['function']['max']} | {s['file']['mean']} | "
                         f"{s['project']['total']} | {t['total_seconds']} |")
    return "\n".join(lines) + "\n"


def score(label: str) -> dict:
    """Rating counts per model and level, from eval/explain/<target>/review.json."""
    out: dict = {}
    for name in PER_TARGET:
        review = json.loads((EVAL / "explain" / name / "review.json").read_text(encoding="utf-8"))
        for model, items in review["runs"][label].items():
            for item in items.values():
                c = out.setdefault(model, {}).setdefault(item["level"], Counter())
                c[item["rating"]] += 1
    table = {m: {lvl: {r: c[r] for r in RATINGS} | {"n": sum(c.values())} for lvl, c in levels.items()}
             for m, levels in out.items()}
    print(json.dumps(table, indent=2))
    return table


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--draw-sample", action="store_true")
    parser.add_argument("--label")
    parser.add_argument("--models", nargs="+", default=list(MODELS))
    parser.add_argument("--score", metavar="LABEL")
    args = parser.parse_args()
    if args.draw_sample:
        print(json.dumps(draw_sample(), indent=2))
    if args.label:
        run(args.label, args.models)
    if args.score:
        score(args.score)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
