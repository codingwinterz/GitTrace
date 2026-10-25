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
  the app's default `admin`/`admin123`. I did not read this file when writing the
  ground truth. It is test data, not a vulnerability.
- `vulnpy/apps/django_app.py` (B105): Bandit reports the allowlisted `"SECRET_KEY": "test_key"`
  at the start of the enclosing dict (lines 23–25), not at line 27, so it is scored
  as an ordinary false positive rather than a benign one.

## Reproduce

```bash
python eval/run_eval.py            # needs git and network for the first clone; Bandit is installed into eval/.bandit-venv
```
