# GitTrace evaluation

Measures GitTrace's rules against deliberately vulnerable Flask/FastAPI apps with
hand-written ground truth, compares Bandit on the same five categories, and checks
the false-positive rate on maintained real-world projects.

## Protocol

1. Each target is pinned to a commit (`targets.json`).
2. For each vulnerable app, `eval/<target>/ground_truth.json` lists the
   vulnerabilities in GitTrace's five categories (SQL injection, eval/exec/compile,
   shell command injection, unsafe deserialization, hardcoded secrets), written from
   the project's own documentation and a reading of the code **before** either tool
   was run on it. Each entry gives the file, the acceptable lines (the dangerous call,
   and the line that builds the dangerous string, since Bandit's SQL check reports
   the latter), and whether a route really reaches it.
3. `benign` entries are dangerous-looking patterns that are not vulnerabilities
   (e.g. SQL formatted from constants in a seed script). In the headline numbers a
   tool reporting one gets a false positive; precision is also shown with them
   ignored.
4. `run_eval.py` clones/checks out each target, runs `gittrace scan --offline
   --no-blame --format json` and Bandit (JSON), maps Bandit's test ids to the five
   categories (below), matches findings to ground truth by file and line, and
   writes `results/`. No rule was changed between writing the ground truth and the
   first ("untouched") run.

Bandit tests counted, by category (all other Bandit tests are ignored):

| Category | Bandit tests |
|---|---|
| sql-injection | B608, B610, B611 |
| code-injection | B102 (exec), B307 (eval) |
| command-injection | B602, B604, B605 |
| unsafe-deserialization | B301 (pickle/marshal/dill), B302 (marshal), B506 (yaml.load) |
| hardcoded-secret | B105, B106, B107 |

Import-only warnings (B403 `import pickle`, B404 `import subprocess`) and
subprocess calls without a shell (B603, B607) are not vulnerabilities in these
categories and are not counted.

## Notes found after the first run (ground truth left unchanged)

The ground-truth files were not edited after the run; `ground_truth.sha256` holds
their hashes from before it. Two Bandit hits fall on lines the ground truth did not
anticipate. Neither changes any count, because both are false positives either way:

- `vulnerable-flask-app/tests/e2e_zap.py:15` (B105): a ZAP test script logs in with
  the app's default `admin`/`adm*****`. I did not read this file when writing the
  ground truth. It is test data, not a vulnerability.
- `vulnpy/apps/django_app.py` (B105): Bandit reports the allowlisted `"SECRET_KEY": "test_key"`
  at the start of the enclosing dict (lines 23–25), not at line 27, so it is scored
  as an ordinary false positive rather than a benign one.

## Runs

| Label | Targets | Rules | Notes |
|---|---|---|---|
| `untouched` | the four vulnerable targets, CTFd, mealie | as committed in Phase 4 (94af77b) | first run; ground truth written before it |
| `after-tuning` | the same | fixes 1-8 approved after `untouched` | optimistic: the fixes were chosen from these targets |
| `after-reachability` | the four vulnerable targets, CTFd, mealie | the tuned rules plus Flask-RESTful/RESTX routes and auth checks at the top of handler bodies | detection rules unchanged; the body-check condition rule was tightened after a first run of this label showed 401/403 guards on a form field, a user limit and feature flags, so it is tuned on these targets; held-out targets not re-run (run once) |
| `after-reach-fixes` | the four vulnerable targets, CTFd, mealie (reachability only: `results/after_reach_fixes.json`) | unchanged | Falcon routes, Flask `add_url_rule` (also in loops) and thread targets; measured with `scan` against the graph, compared Sink by Sink with `results/after_reachability_port.json`; the run label and commit are in the file |
| `held-out` | DVGA, open-webui | the tuned rules (`held_out_code.sha256`) | chosen and read only after the fixes were final; run once with `--targets held-out`, nothing changed afterwards; the open-webui review was folded in with `--review-only`, without re-scanning |

Real-world reviews (`eval/<project>/review.json`) are keyed by finding id. A
finding that only appeared after tuning was reviewed in the after-tuning run
and is marked as such (CTFd `config.py:308`).

## Reachability

Counted over GitTrace's true positives on the four vulnerable targets, from the
committed files: a true positive is *truly reachable* when its ground-truth entry
(`eval/<target>/ground_truth.json`) lists at least one route, and *marked* when a
finding matched to it (`results/<label>/<target>.json`) has `reachable: true`.

| | `untouched` | `after-tuning` | `after-reachability` | `after-reach-fixes` |
|---|---|---|---|---|
| True positives | 23 | 29 | 29 | 29 |
| Truly reachable | 20 | 20 | 20 | 20 |
| Marked reachable (correctly / wrongly) | 7 (7 / 0) | 7 (7 / 0) | 7 (7 / 0) | 7 (7 / 0) |
| Marked reachable without auth (correctly / wrongly) | 7 (6 / 1) | 7 (6 / 1) | 6 (6 / 0) | 6 (6 / 0) |

The 13 truly reachable true positives not marked are all in vulnpy, the same in
every run: 11 are reached through `getattr` dispatch (`import_module` plus
`getattr(module, "do_" + name)`, with routes added in loops; VP-2, VP-6 to VP-15),
and 2 through Falcon routes (VP-4, VP-5). From `after-reach-fixes` GitTrace detects
Falcon routes, but vulnpy's app is rebound under a condition
(`app = ContrastMiddleware(app)`), so it is not resolved and the 2 stay unmarked;
the new thread edge gives VP-5's function its caller (`ThreadView.on_get`, blast
radius 0 -> 1), still with no route. The one
wrongly marked without auth before `after-reachability` is VF-1, whose JWT is
checked inside the handler.

## Model triage (Phase 5)

`run_triage.py` measures the model's triage of GitTrace's findings on the labels
above, which were all written before any model saw a finding:

- **Labels.** On the vulnerable targets, a finding matching a ground-truth
  vulnerability (scored exactly as `run_eval.py` does) is a true positive; one
  matching a `benign` entry or nothing is a false positive. On the real-world
  projects, the verdict in `review.json`.
- **Sets.** *Measured*: vulpy-bad, vulpy-good, vulnerable-flask-app, vulnpy,
  DVGA, CTFd, mealie (52 findings: 35 TP, 17 FP), the rules as tuned. *Held out*:
  open-webui (29 findings: 2 TP, 27 FP), set aside before the first triage run
  and used only to check a tuned prompt, once.
- **Runs.** Both models (`qwen2.5-coder:7b`, `llama3.1:8b`, Q4_K_M in Ollama),
  one at a time, no cache, after one untimed warm-up call. The `untouched` run
  uses the prompt as first written (`triage-v1`), developed on
  `tests/fixtures/sample_app` only; nothing is changed during it. Any tuning
  afterwards gets a new prompt version and is reported separately as
  `after-tuning` (optimistic: tuned on the same findings) and `held-out`.
- **Numbers.** The share of false positives marked `likely_harmless`, the share
  of true positives marked `likely_harmless` (the one that matters most: a
  security tool must not hide real issues), the share `uncertain`, and the
  model's seconds per finding on an RTX 5050 Laptop GPU (8 GB). Each run also
  records the hash of `gittrace/llm/*.py` that produced it.
- **Injection probe.** `--probe-injection <run>` triages every true positive
  again with a comment above the flagged line telling the model the call is
  safe and asking for `likely_harmless` with −2, and counts the flips.

Triage runs (each in `results/triage/<label>/`: `summary.md`, and one JSON per
model with every finding's label, verdict, value sources, reason, adjustment,
seconds and fix check; each records the hash of `gittrace/llm/*.py`):

| Label | Prompt | Set | Notes |
|---|---|---|---|
| `untouched` | `triage-v1` (`system_prompt_triage-v1.txt`) | measured | written and tried on `sample_app` only, nothing changed during the run |
| `after-tuning-1` | `triage-v2` (`system_prompt_triage-v2.txt`) | measured | value sources before the verdict; optimistic (tuned on these findings) |
| `after-tuning-2` | `triage-v3` (`after-tuning-2/system_prompt_triage-v3.txt`) | measured | secret guidance corrected after round 1; optimistic |
| `held-out` | `triage-v3` | open-webui | run once after tuning was final; nothing changed afterwards |
| `after-tuning-2-injection` | `triage-v3` | measured TPs | the injection probe, against `after-tuning-2`'s clean verdicts |
| `no-fix-paragraph` | `triage-v3-nofix` (`system_prompt_triage-v3-nofix.txt`) | measured | Phase 6 trial: the fix instructions removed from the prompt. Hid more true positives (llama3.1:8b 3 of 35, one a command injection; qwen2.5-coder:7b 11) and was not adopted |
| `default-no-fix` | `triage-v3`, `fix_code` constrained to null | measured | `scan` without `--fix` (`--no-fix` here): same verdict, adjustment and value sources as `after-tuning-2` for 52 of 52 findings, both models |
| `after-tuning-3` | `triage-v4` (in `gittrace/llm/prompts.py`) | measured | the severity adjustment counts only what the rules' score does not (the prompt lists the factors already scored). TP marked harmless: qwen2.5-coder:7b 10 → 9, llama3.1:8b 1 → 1; mean TP adjustment llama3.1:8b +0.37 → −0.06. Labelled `after-tuning-3` because `after-tuning-2` is triage-v3's run. Held-out set not re-run |

Caveat on the held-out set: open-webui's `review.json` (with reasons) was
written in the rules evaluation and had been read during this work before the
prompt was tuned, so it is held out from the model, not entirely from the
person tuning the prompt. The guidance added in tuning cites only cases found
in the measured set (mealie's migration SQL and bind-parameter names, CTFd's
`TestingConfig` key, mealie's default passwords, vulpy's weak key).

```bash
python eval/run_triage.py --label untouched
python eval/run_triage.py --label after-tuning-2-injection --probe-injection after-tuning-2
python eval/run_triage.py --label held-out --set held-out      # only after tuning, once
python eval/run_triage.py --label default-no-fix --no-fix
python eval/run_triage.py --label after-tuning-3
```

## Explain (Phase 6)

`run_explain.py` measures `gittrace explain`'s model summaries on two targets
(`explain/targets.json`): `tests/fixtures/sample_app`, and
[miguelgrinberg/microblog](https://github.com/miguelgrinberg/microblog) at a
pinned commit, a small real-world Flask app not used anywhere else in this
project (SQLAlchemy, Elasticsearch, Redis/RQ, email, an HTTP translation API,
a JSON API with token auth, Flask CLI commands, Alembic migrations).

- **Before any summary existed:** the sample of 30 functions was drawn (seed
  7) from the functions `explain` summarises by default (10 from sample_app,
  20 from microblog; `explain/sample.json`), and a reference note was written
  for every file and every sampled function from the code
  (`explain/<target>/reference.json`). Both are hashed in
  `explain/reference.sha256`. Drawing the sample needed only GitTrace's
  deterministic facts; no model was called on either target before. One
  change to the facts came after the draw and before any summary: Flask CLI
  commands (`@bp.cli.group()`) became entry points. It added microblog's four
  CLI functions to the important ones; every sampled function was still
  important.
- **Runs:** both models, one at a time, no cache, after one untimed warm-up
  call; every file, the project, and the important functions, as `explain`
  does by default. Each record keeps the summary, its seconds, its grounding
  check and what was cut to fit.
- **Review:** every file summary and the 30 sampled function summaries, for
  both models, rated against the reference and the code: **correct** (every
  statement true, main purpose covered), **partly** (main purpose right, but a
  false or misleading detail, or a key point of the reference missing), or
  **wrong** (main purpose wrong, or a central claim false), with a reason
  (`explain/<target>/review.json`).
- **Untouched first:** the first run (`untouched`) uses the prompts as first
  written (`explain-v1`, developed on `tests/fixtures/flask_app` only; archived
  in `results/explain/untouched/system_prompts_explain-v1.txt`).
- **Who rated:** the ratings were made by an AI (Claude, the coding agent
  building this project) against the pre-written references and the code,
  plus any spot checks the owner makes; they are not independent human
  judgments.
- **After tuning** (`after-tuning`, `explain-v2`): the same targets, sample
  and protocol after the changes chosen from the untouched results: a fake
  example id in the prompt, side effects defined to include reads, more
  side-effect facts (Flask-SQLAlchemy helpers, Elasticsearch/OpenSearch,
  Redis and task queues as `store_read`/`store_write`, HTTP client objects,
  email, more file APIs, the object's type from the resolver), and the
  glossary's "Terms used" attached in code. Optimistic: the changes were
  chosen from these two targets. The review criteria are unchanged except
  that `side_effects: none` for a function that reads the database (or a
  search index) now counts as a false detail, because explain-v2 defines
  side effects to include reads.
- **Held out** (`held-out`): [testdrivenio/fastapi-tdd-docker](https://github.com/testdrivenio/fastapi-tdd-docker)
  at a pinned commit (`explain/targets_held_out.json`), a small FastAPI app
  (Tortoise ORM, a background summarizer task, pydantic settings, an aerich
  migration) chosen after tuning was final and not used anywhere else in
  this project. Its sample (all 7 important functions, `explain/sample_held_out.json`)
  and its references (`explain/fastapi-tdd-docker/reference.json`) were
  written and hashed (`explain/reference_held_out.sha256`) before any model
  ran on it. Run once; nothing was changed because of it. It ran with the
  same code as `after-tuning` (explain code sha256 `a8aadf04f8c1`); the only
  later edits under `gittrace/llm/` are the per-model time estimate and a
  comment, which do not reach any prompt.
- **Timing** (`timing`): both models on the measured targets with
  `--require-ac`, which stops unless the laptop is on AC power and records
  the power state before and after each model. Reported separately from the
  quality runs, whose seconds are not comparable (`power_at_start`,
  `power_before`, `power_after` in each `summary.json`).
- **Plain language:** `--terms` counts, for every run, the summaries whose
  prose uses a term of GitTrace's glossary (`gittrace/core/glossary.py`),
  recomputed from the recorded text with the same check for every run.

```bash
python eval/run_explain.py --draw-sample          # once
python eval/run_explain.py --label untouched
python eval/run_explain.py --score untouched
python eval/run_explain.py --label after-tuning
python eval/run_explain.py --terms untouched after-tuning
python eval/run_explain.py --set held-out --draw-sample          # once, before any model run on it
python eval/run_explain.py --set held-out --label held-out       # once, after tuning
python eval/run_explain.py --label timing --require-ac
```

Results (`results/explain/<label>/`; ratings in `explain/<target>/review.json`,
made by an AI against the references, see "Who rated" above):

| Run | Model | Files correct / partly / wrong | Functions correct / partly / wrong | Mentions kept / removed |
|---|---|---|---|---|
| `untouched` | llama3.1:8b | 35 / 10 / 2 (of 47) | 24 / 5 / 1 (of 30) | 270 / 9 |
| `untouched` | qwen2.5-coder:7b | 42 / 5 / 0 | 28 / 2 / 0 | 294 / 6 |
| `after-tuning` | llama3.1:8b | 38 / 8 / 1 | 26 / 3 / 1 | 239 / 6 |
| `after-tuning` | qwen2.5-coder:7b | 45 / 2 / 0 | 29 / 1 / 0 | 279 / 3 |
| `held-out` | llama3.1:8b | 14 / 4 / 0 (of 18) | 4 / 3 / 0 (of 7) | 57 / 3 |
| `held-out` | qwen2.5-coder:7b | 16 / 2 / 0 | 3 / 4 / 0 | 70 / 7 |

Glossary terms (`results/explain/terms.json`): summaries whose prose uses at
least one term, llama3.1:8b / qwen2.5-coder:7b: untouched 85 / 82 of 102,
after tuning 84 / 86 of 102, held out 20 / 18 of 26. From explain-v2 on,
every one of them carries GitTrace's definitions ("Terms used").

Held-out finding, not fixed: GitTrace found no side effects at all in
fastapi-tdd-docker (the Tortoise ORM, newspaper's downloads and
`nltk.download` are not classified), and 3 (llama3.1:8b) and 4
(qwen2.5-coder:7b) of the 7 function summaries repeat "none" for handlers
that read or write the database.

The seconds in the quality runs are not comparable between runs or models
(battery power, model loads); see the `timing` run.

Code hashes (explain code sha256 covers `gittrace/llm/*.py`, `gittrace/core/explain.py`,
`gittrace/core/glossary.py` and `gittrace/languages/python/facts.py`; each run's
`summary.json` records it):

| Code | explain code sha256 | gittrace/llm sha256 | What changed |
|---|---|---|---|
| `after-tuning`, `held-out` | `a8aadf04f8c1` | `7f62a40da270` | the measured explain-v2 code |
| `timing` | `17b003bf97de` | `edbf0c30a4cb` | the per-model time estimate and a comment |
| Phase 7 | `8665e416d4ef` | `4abb331f2884` | triage prompt v4 (`prompts.py`, `context.py`; explain uses neither its prompt nor its finding block, only the unchanged `fence` and `estimate_tokens`) and the time estimate set from the `timing` run: 2.1 s per call for both models |
| Gateway (current; not re-measured) | `fbc156c36353` | `ffcd4da1e90e` | the optional Respan Gateway path: `gateway.py` added, `client.py` and `llm/__init__.py` route to it when `GITTRACE_GATEWAY=1` (no explain prompt, facts or glossary file changed) |

No change up to Phase 7 reaches an explain prompt, so the quality runs
still describe that code. The recorded explain results were produced before
the gateway change (explain code sha256 `8665e416d4ef`); the files that hash
covers have changed since (now `fbc156c36353`), and the explain eval was not
re-run for them.

Timing (`results/explain/timing/`, `--label timing --require-ac`): both
models back to back on the measured targets, 102 calls each, llama3.1:8b
first, power plan "Turbo", AC before and after each model. The laptop went
into Modern Standby twice during the run while plugged in, and each pause
fell inside one call: llama3.1:8b's microblog `create_app` (recorded 1524 s)
and qwen2.5-coder:7b's sample_app `version` (331 s); see
`results/explain/timing/NOTES.md`. The raw `summary.md` includes those two
calls; the figures here leave them out. Every other call took 1.1 to 8.4 s.

| AC, seconds per call, median (mean) | llama3.1:8b | qwen2.5-coder:7b |
|---|---|---|
| function (52 each) | 1.86 (1.95) | 2.04 (2.14) |
| file (47 each) | 2.31 (2.54) | 2.16 (2.40) |
| project (2 each) | 7.2 (7.2) | 6.2 (6.2) |
| every call (101 each) | 2.08 (2.33) | 2.13 (2.34) |

On AC the two models are equally fast (one run, no repeats; the 0.1 to 0.2 s
differences are not a ranking), and there is no 3x difference. Calls took
about a quarter less time than in the after-tuning run on battery (median
2.08 against 2.78 s, 2.13 against 2.76 s).

A battery pass (`timing-battery`, both models back to back, the charge
falling to 16%) is kept but not used to compare the models: the second model
ran on a lower charge and was about 2.7x slower than in the after-tuning run.

## No raw secrets in the output

GitTrace masks hardcoded secrets in its reports, but eval output also carries
text it does not produce: ground-truth `detail`, review `reason` (copied into
the triage records as the label `source`), Bandit's code snippets, and the
context lines of a fix diff (which can hold a secret the rule misses, e.g.
Vulnerable-Flask-App's `SECRET_KEY_HMAC`). After the Phase 5 runs a hygiene
check found mealie's default admin password verbatim in six triage result
files, copied from a review reason, and a fuller check found more of the same
kind (mealie's default Postgres password, open-webui's default admin password,
and ground-truth and Bandit lines in the rules evaluation).

`hygiene.py` now keeps them out:

- `eval/secret_values.sha256` lists the sha256 of every secret value in the
  pinned targets (the hardcoded-secret rule's values plus the values the
  ground truths quote, which covers the rule's misses). Only hashes are
  committed. `python eval/hygiene.py --update` rebuilds it from the checkouts;
  both eval scripts add their targets' values on every run.
- `run_eval.py` and `run_triage.py` write every output file through
  `hygiene.scrub`, which replaces a listed value by the rule's mask (first 3
  characters kept), and stop with an error if any output still holds one.
- `tests/test_eval_hygiene.py` (in CI) fails if any committed file under
  `eval/results/` or any `review.json` holds a listed value.

A plain lower-case word (`admin`, `mealie`) is only a leak right after a
secret word (`password 'mea***'`), not in `username = 'admin'`.

The existing results and review files were scrubbed in place with `python
eval/hygiene.py --scrub`: only the quoted values changed, no verdict, label
or number. The ground-truth files keep their text, because
`ground_truth.sha256` shows they were written before any tool ran.

## Reproduce

```bash
python eval/run_eval.py --label untouched        # at commit e08d091 (the rules before tuning)
python eval/run_eval.py --label after-tuning
python eval/run_eval.py --targets held-out --label held-out
# needs git and network for the first checkout; Bandit is installed into eval/.bandit-venv
```
