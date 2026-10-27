# Changelog

All notable changes to GitTrace. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the version numbers follow [Semantic Versioning](https://semver.org/).

## [2.0.0] — unreleased (`v2` branch)

A rebuild as a command-line tool that scans real Python projects. The measured results are
in the README ("Results at a glance") and `eval/`.

### Added

- **Packaging (Phase 7):** `pyproject.toml` with the `gittrace` and `gittrace-mcp` commands
  (`pipx install .`); `gittrace --version`.
- **`gittrace doctor`:** checks Python, Docker, FalkorDB (a real round trip), whether the
  database is local, Ollama and both models, free GPU memory, and on Windows power and sleep
  settings. **`gittrace up [--pull]`** starts local FalkorDB in Docker and pulls missing models.
  **`gittrace graphs [--drop NAME] [--allow-remote]`** lists or deletes graphs.
- **Settings:** read from environment variables or the first of `$GITTRACE_ENV_FILE`, a
  checkout's `.env`, and the user config directory; never the current directory's `.env`.
- **Interactive mode:** `gittrace` alone in a terminal opens a Textual session with slash
  commands, history, a status line and an animated graph logo (`--no-anim`).
- **`gittrace explain` (Phase 6):** plain-language facts (entry points, endpoints, modules,
  libraries, services, side effects, request flows) and model summaries of the project, its
  files and its important functions, with a grounding check against the call graph and
  glossary definitions.
- **Model triage (Phase 5):** a local model (Ollama via LiteLLM, `llama3.1:8b` by default)
  gives each finding a verdict, a reason and a −2..+1 severity adjustment shown beside the
  rules' score; `--fix` adds a diff checked with `git apply --check`; replies validated,
  retried once, cached.
- **`gittrace scan` (Phase 4):** rules for SQL built from strings, `eval`/`exec`, shell
  commands, unsafe deserialization and hardcoded secrets; route-to-sink reachability;
  blast radius; `git blame` owner; deterministic severity; `--fail-on` for CI; `trace` and
  `blast-radius`.
- **Ingestion (Phase 3):** tree-sitter parsing into a FalkorDB graph with stable function ids,
  call resolution, and FastAPI / Flask routes with auth evidence.
- **Evaluation:** ground truth written before running anything; untouched, after-tuning
  and held-out runs against Bandit, for triage, and for explain.

### Changed

- **Database safety:** local Docker is the default; `scan` refuses to write to a remote
  FalkorDB without `--allow-remote`; host, port and password are never printed; the
  integration tests run only against a local database.
- **Triage prompt `triage-v4`:** the severity adjustment no longer double-counts what the
  rules already scored (reachability, parameter derivation, blast radius). Real issues
  marked harmless: llama3.1:8b 1 of 35 (unchanged), qwen2.5-coder:7b 9 of 35 (was 10).
- **Privacy:** the git blame email is hidden unless asked for (`scan --show-email`,
  `GITTRACE_SHOW_EMAIL=1` for the MCP tools).
- **Display:** secret findings no longer show the model's "attacker input" line, and a parse
  failure is reported once.
- **`explain`'s time estimate** uses the AC-power measurement: 2.1 s per model call.
- **Restructured** into `gittrace/core`, `graph`, `languages/python`, `rules`, `llm` and `cli` (Phase 2).

### Removed

- The FastAPI web routes and the `frontend/` app (still in the `v1.0.0` tag).

### Security

- `git` runs on scanned repositories with `core.fsmonitor` off and without `textconv`.
- Tracebacks never print local variables.

### Fixed

- Blast radius counted callees instead of callers; function lookups used substrings (Phase 1).

## [1.0] — 2026-10-19 (tag `v1.0.0`)

The Graph Hacks submission: a CVE blast-radius agent over FalkorDB with a web UI, an HTTP
API, a synthetic demo graph and an MCP server. See the `v1.0.0` tag and its demo video.
