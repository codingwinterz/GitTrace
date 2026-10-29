# Changelog

All notable changes to GitTrace. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the version numbers follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

GitTrace no longer needs Docker, Redis or a database server: `pipx install` and run.

### Added

- **Falcon routes:** `app.add_route("/a", Resource())` on `falcon.App` / `falcon.API` /
  `falcon.asgi.App`, one endpoint per responder (`on_get`, `on_post`, ...; `suffix=`).
- **Flask `add_url_rule`**, also in loops: an endpoint when the view resolves; a computed rule
  is kept as `${...}` with `prefix_resolved: false`.
- **Thread targets:** `threading.Thread(target=f)` is a `dynamic` call edge to `f`.
- **Model layer through the Respan Gateway:** `GITTRACE_GATEWAY=1` routes scan triage,
  `explain` summaries and `--fix` through an in-process
  [Respan Gateway](https://github.com/respanai/respan-gateway) (`respan-gateway==0.3.0`, the optional `gateway` extra:
  `pipx install --force "gittrace[gateway] @ git+https://github.com/codingwinterz/GitTrace"`;
  configured by `GITTRACE_GATEWAY_CONFIG` or the provider keys in the environment) instead of
  LiteLLM calling the provider directly. The same prompt, JSON schema, timeout and errors;
  the gateway's model names, routes and provider keys. Off by default, no Respan account or
  credits involved, and the `gateway.toml` of the scanned project is never read.

### Changed

- **The graph is in-process:** FalkorDB is replaced by a NetworkX graph held in memory
  (`gittrace/graph/memstore.py`) and cached in `<project>/.gittrace/graph.json`, written
  atomically with the sha256 of every source file. A cache is never used once any source file
  is changed, added or removed; the graph tools then ask for a new `scan`. Function source code
  is not cached. The graph tools keep their names, arguments and result shapes, and reachability
  is unchanged on the evaluation targets (`eval/results/baseline_reachability.json` and
  `after_reachability_port.json` are identical, Sink by Sink; neither records a run label, so their
  counts are not cited here; see `eval/README.md`, Reachability).
- **`gittrace up [--pull]`** now only checks Ollama and pulls missing models.
- **`gittrace doctor`** no longer checks Docker, FalkorDB or the database location.
- **Interactive mode:** the header no longer shows a database status.

### Removed

- The `gittrace graphs [--drop NAME]` command.
- `scan --allow-remote` and `/scan --allow-remote` (there is no remote database to write to).
- Starting a FalkorDB container from `gittrace up`.
- The `docker`, `falkordb` and `database` checks of `gittrace doctor`.
- The `FALKORDB_HOST`, `FALKORDB_PORT`, `FALKORDB_USER` and `FALKORDB_PASSWORD` settings.
- `docker-compose.yml`, the FalkorDB service in CI, and the `falkordb` and `redis` dependencies
  (`networkx` is added).

## [2.0.0] — 2026-10-27

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
- **Flask-RESTful / Flask-RESTX routes:** `api.add_resource(Resource, "/url")` and
  `@api.route` / `@ns.route` on a class; each verb method is a handler; `Api`, `init_app`,
  `Namespace` and `add_namespace` prefixes; `method_decorators` count as auth evidence.
- **Auth checks in the handler body:** a token-verifying call (`jwt.decode`,
  `verify_jwt_in_request`, `verify_token`-like names) or a 401/403 guard on the caller's
  identity among the handler's first five statements marks the route as authenticated.
- **Evaluation:** ground truth written before running anything; untouched, after-tuning
  and held-out runs against Bandit, for triage, and for explain; an `after-reachability` run
  for the two route changes above (detection unchanged; of 20 truly reachable true positives, marked
  reachable: `untouched`: 7 marked, 0 wrong; `after-reachability`: 7 marked, 0 wrong; marked
  reachable without auth: `untouched`: 7 marked, 1 wrong; `after-reachability`: 6 marked, 0 wrong).

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
- **Interactive mode:** `/help` is a compact two-column list (descriptions under their
  command below 80 columns), and the header shows the scan and explain models on separate lines.
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
