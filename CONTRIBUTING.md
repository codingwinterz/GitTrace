# Contributing to GitTrace

Thanks for looking. Small, focused pull requests are easiest to review; for anything larger,
open an issue first so we can agree on the approach.

## Set up

```bash
git clone https://github.com/codingwinterz/GitTrace && cd GitTrace
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt                        # this checkout, editable, plus pytest and build
gittrace up --pull                                     # local FalkorDB in Docker, and the Ollama models
gittrace doctor
```

Python 3.11 or newer. No `.env` is needed: the defaults are local Docker and local Ollama.

## Run the tests

```bash
python -m pytest tests -q                               # everything; DB and model tests skip if absent
GITTRACE_REQUIRE_FALKORDB=1 python -m pytest tests -q   # fail instead of skipping without FalkorDB
```

- Offline suites mock the database and the model; the integration suites
  (`tests/test_*_integration.py`) run against a **local** FalkorDB only and drop the graphs they
  create; `tests/test_llm_live.py` makes one real call to Ollama.
- CI runs the offline suites on Python 3.11–3.13, the integration suites against a FalkorDB
  service, and builds, installs and smoke-tests the package on Linux and Windows.
- Every Cypher query must be tested against a real FalkorDB, not only with mocked results.

## Rules of the codebase

These come from `CLAUDE.md`, the project plan, and are not up for casual change:

1. **Rules detect, the model explains.** A finding comes from a deterministic rule. The model
   may comment on it, never create, remove or gate it.
2. **Fixes are shown as diffs, never applied.**
3. **Stable ids:** a function is `relative/path.py::QualifiedName`. Never match by bare name or substring.
4. **Graph writes use `MERGE` on stable ids**, so a re-scan is idempotent.
5. **Language support is a plug-in** (parser, rules, route detector behind one interface); Python only for now.
6. **Scanned code is untrusted input**, to the parser and to the model (see `SECURITY.md`).
7. **Never print a database host, port or password**, or a raw secret value.

Code style: match the surrounding code (its naming, comment density and idioms). Each module
starts with a docstring saying what it does and what it deliberately does not.

## Adding or changing a rule

A rule is a module under `gittrace/rules/` whose docstring states what it matches and what it
does not. Add positive and negative cases to `tests/test_rules.py`; if `tests/fixtures/sample_app`
changes, update `tests/expected_findings.py` and the snapshot
(`GITTRACE_UPDATE_SNAPSHOTS=1 pytest tests/test_scan.py -k snapshot`) and review the diff.
Severity points live in `gittrace/core/severity.py` and the README table; change both together.

## Changing a prompt, or anything measured

The numbers in the README come from `eval/`, under rules that keep them honest:

- **Ground truth before results.** Labels, references and samples are written (and hashed)
  before any tool or model runs on a target.
- **Separate, labelled runs.** Untouched, after-tuning and held-out results are kept apart,
  never overwritten; a new prompt version gets a new run label.
- **Held-out targets are run once**, after tuning, and nothing is changed because of them.
- **Bump the version** when you change a prompt or its layout: `PROMPT_VERSION` in
  `gittrace/llm/prompts.py` (triage) or `EXPLAIN_VERSION` in `gittrace/llm/explain.py`. It is part
  of the cache key, and the eval records it.
- **The key triage number** is real issues marked `likely_harmless`. A prompt change that raises
  it is reverted.
- **No raw secrets in `eval/` output**: `eval/hygiene.py` and `tests/test_eval_hygiene.py` enforce it.

See `eval/README.md` for the scripts.

## Commits and pull requests

- Describe what changed and why; mention any measured number that moved.
- Keep generated files (`eval/results/...`) in the same commit as the code that produced them.
- Never commit `.env`. CI must be green.

## Maintainer notes

- **Branches:** `main` (the default) holds the CLI (v2); `v2` is kept as the development
  branch; the 1.0 web app is the tag `v1.0.0`.
- **Pushing:** check `git status` for only the files you meant to change, run at least the
  offline suites, push, then confirm it landed with `git log --oneline -1 origin/<branch>`.
- **No secrets before every push.** `.env` is gitignored and must stay that way: it can hold
  the FalkorDB password and a hosted model's API key. Check the tracked tree, not just the
  working directory:

  ```bash
  git ls-files | grep -i '\.env$'                                 # must print nothing
  git grep -nE 'AIza[0-9A-Za-z_-]{10,}|AQ\.[A-Za-z0-9_-]{10,}'   # must print nothing
  ```

  If a key ever does get committed, rotate it at its provider first (a force-push does not
  un-leak it), then rewrite history.
- Do not commit `*.log`, `debug/`, `.venv/`, `__pycache__/` or `.pytest_cache/`; all are
  already in `.gitignore`.
