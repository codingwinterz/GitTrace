# Run GitTrace locally

One-page, clone-to-run companion to README.md. For the rules, severity model, graph
model, Cypher queries, and the MCP server, see README.md. Demo video (of the 1.0 web
UI, tag `v1.0.0`): <https://youtu.be/xwo16Zesdus>.

## Fastest start

Run every command from the repository root.

```bash
pip install -r requirements.txt                             # editable install: puts `gittrace` on PATH
gittrace up --pull                                          # FalkorDB in Docker + both Ollama models
gittrace doctor                                             # everything ready?
# No .env needed for local Docker: localhost:6379 without a password is the default.

gittrace scan tests/fixtures/sample_app           # findings, attack paths, owner
gittrace scan path/to/project --format json       # for CI; exit 1 at --fail-on (default high)
gittrace trace app/db.py:17 -p tests/fixtures/sample_app
gittrace blast-radius app/db.py::Repo.get_user -p tests/fixtures/sample_app
gittrace scan path/to/project --offline           # no FalkorDB needed
gittrace scan path/to/project --no-llm            # rules only, no model calls
gittrace scan path/to/project --model ollama/qwen2.5-coder:7b   # another model
gittrace scan path/to/project --fix               # also a checked fix diff per finding

gittrace explain path/to/project                  # plain-language tour: facts + summaries
gittrace explain path/to/project --no-llm         # facts only (entry points, endpoints, flows)
gittrace explain path/to/project --out EXPLAIN.md # keep it as a Markdown file
gittrace explain path/to/project --file app/db.py # one file (and all its functions)
gittrace explain path/to/project --function app/db.py::Repo.get_user

gittrace                                          # interactive mode (/help inside; --no-anim for a still logo)
```

`scan` asks a local model to triage each finding, and `explain` to summarise the code.
Install [Ollama](https://ollama.com) and pull the default models once (`ollama pull llama3.1:8b`
for triage, `ollama pull qwen2.5-coder:7b` for `explain`), or pass `--no-llm`. Replies are cached in `<project>/.gittrace/cache`, so a rerun on unchanged
code makes no model calls. `explain` estimates its run time first and asks before anything over
10 minutes (`--yes` skips the question).

Severity, the rules and the graph model are documented in README.md.

## Env vars

See `.env.example`. FalkorDB defaults to local Docker (localhost:6379, no password). Any other
host is remote: `scan` warns and needs `--allow-remote` to write graphs there, and GitTrace only
ever says "local" or "remote", never the host, port or password.
`GITTRACE_MODEL` picks the triage model and `GITTRACE_EXPLAIN_MODEL` the `explain` model
(`--model` wins over both), `GITTRACE_LLM_TIMEOUT`
the seconds to wait per reply, `OLLAMA_API_BASE` where Ollama listens. Never commit `.env`.

## Tests

```bash
python -m pytest tests -v
```

`tests/test_core.py`, `tests/test_ingest.py`, `tests/test_rules.py`, `tests/test_scan.py` and
`tests/test_llm.py` are offline (no live DB, the model mocked), as are `tests/test_logo.py` and
`tests/test_interactive.py` (the interactive mode, driven headless). `tests/test_llm_live.py`
runs one real triage against Ollama and skips when Ollama or the model is not there. `tests/test_ingest_integration.py` and
`tests/test_scan_integration.py` scan `tests/fixtures/sample_app` into a real FalkorDB and
check the exact graph, findings and tool results; they create their graphs and drop them.

```bash
docker compose up -d falkordb
FALKORDB_HOST=localhost FALKORDB_PORT=6379 FALKORDB_PASSWORD= python -m pytest tests/test_ingest_integration.py tests/test_scan_integration.py -v
```

(Environment variables win over `.env`, so this works even with cloud settings in `.env`; with a
remote `FALKORDB_HOST` the integration tests skip rather than write graphs there.)
Without a reachable FalkorDB the integration tests skip. CI runs them against a FalkorDB
service container and sets `GITTRACE_REQUIRE_FALKORDB=1`, which turns that skip into a
failure.

Run at least the offline suites before pushing. CI (`.github/workflows/tests.yml`) runs
them on Python 3.11–3.13, plus the integration suites against FalkorDB in Docker:

```bash
python -m pytest tests/test_core.py tests/test_ingest.py tests/test_rules.py tests/test_scan.py tests/test_llm.py tests/test_logo.py tests/test_interactive.py -q
```

## MCP server (Track 01)

```bash
python -m gittrace.mcp_server
```

Stdio transport. Register in your MCP host as:
`{ "command": "python", "args": ["-m", "gittrace.mcp_server"], "env": { "PYTHONPATH": "/path/to/GitTrace" } }`.

## Pushing changes to GitHub

The repo is `https://github.com/codingwinterz/GitTrace` (public). Its default branch
**`main`** holds the CLI (v2); **`v2`** is kept as the development branch, and the 1.0 web
app is the tag **`v1.0.0`**.

```bash
git status                   # confirm only the files you meant to change
python -m pytest tests/test_core.py tests/test_ingest.py tests/test_rules.py tests/test_scan.py tests/test_llm.py tests/test_logo.py tests/test_interactive.py -q

git add gittrace tests README.md RUN.md
git commit -m "Describe the why, not the what"
git push origin v2
```

Then confirm it actually landed:

```bash
git log --oneline -1 origin/v2
```

### Before every push: no secrets

`.env` is gitignored and must stay that way — it holds the FalkorDB password (and any
API key, if you point `GITTRACE_MODEL` at a hosted model). Check the tracked tree, not just the working directory:

```bash
git ls-files | grep -i '\.env$'          # must print nothing
git grep -nE 'AIza[0-9A-Za-z_-]{10,}|AQ\.[A-Za-z0-9_-]{10,}'   # must print nothing
```

If a key ever does get committed, rotate it at its provider first — a
force-push does not un-leak it — then rewrite history.

Do not commit `*.log`, `debug/`, `.venv/`, `__pycache__/`, or `.pytest_cache/`; all are
already in `.gitignore`.
