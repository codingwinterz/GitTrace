# Run GitTrace locally

One-page, clone-to-run companion to README.md. For the rules, severity model, graph
model, Cypher queries, and the MCP server, see README.md. Demo video (of the `main` branch,
which still has the web UI): <https://youtu.be/xwo16Zesdus>.

## Fastest start

Run every command from the repository root.

```bash
pip install -r requirements.txt
docker compose up -d falkordb
cp .env.example .env
# .env: FALKORDB_HOST=localhost, FALKORDB_PORT=6379, FALKORDB_PASSWORD= (empty)

python -m gittrace scan tests/fixtures/sample_app           # findings, attack paths, owner
python -m gittrace scan path/to/project --format json       # for CI; exit 1 at --fail-on (default high)
python -m gittrace trace app/db.py:17 -p tests/fixtures/sample_app
python -m gittrace blast-radius app/db.py::Repo.get_user -p tests/fixtures/sample_app
python -m gittrace scan path/to/project --offline           # no FalkorDB needed
python -m gittrace scan path/to/project --no-llm            # rules only, no model calls
python -m gittrace scan path/to/project --model ollama/qwen2.5-coder:7b   # another model
```

`scan` asks a local model to triage each finding. Install [Ollama](https://ollama.com) and pull
the default model once (`ollama pull llama3.1:8b`), or pass `--no-llm`. Replies are
cached in `<project>/.gittrace/cache`, so a rescan of unchanged code makes no model calls.

Severity, the rules and the graph model are documented in README.md.

## Env vars

See `.env.example`. FalkorDB settings are required except for `scan --offline`.
`GITTRACE_MODEL` picks the triage model (`--model` wins over it), `GITTRACE_LLM_TIMEOUT`
the seconds to wait per reply, `OLLAMA_API_BASE` where Ollama listens. Never commit `.env`.

## Tests

```bash
python -m pytest tests -v
```

`tests/test_core.py`, `tests/test_ingest.py`, `tests/test_rules.py`, `tests/test_scan.py` and
`tests/test_llm.py` are offline (no live DB, the model mocked). `tests/test_llm_live.py`
runs one real triage against Ollama and skips when Ollama or the model is not there. `tests/test_ingest_integration.py` and
`tests/test_scan_integration.py` scan `tests/fixtures/sample_app` into a real FalkorDB and
check the exact graph, findings and tool results; they create their graphs and drop them.

```bash
docker compose up -d falkordb
FALKORDB_HOST=localhost FALKORDB_PORT=6379 FALKORDB_PASSWORD= python -m pytest tests/test_ingest_integration.py tests/test_scan_integration.py -v
```

(Environment variables win over `.env`, so this works even with cloud settings in `.env`.)
Without a reachable FalkorDB the integration tests skip. CI runs them against a FalkorDB
service container and sets `GITTRACE_REQUIRE_FALKORDB=1`, which turns that skip into a
failure.

Run at least the offline suites before pushing. CI (`.github/workflows/tests.yml`) runs
them on Python 3.11–3.13, plus the integration suites against FalkorDB in Docker:

```bash
python -m pytest tests/test_core.py tests/test_ingest.py tests/test_rules.py tests/test_scan.py tests/test_llm.py -q
```

## MCP server (Track 01)

```bash
python -m gittrace.mcp_server
```

Stdio transport. Register in your MCP host as:
`{ "command": "python", "args": ["-m", "gittrace.mcp_server"], "env": { "PYTHONPATH": "/path/to/GitTrace" } }`.

## Pushing changes to GitHub

The repo is `https://github.com/codingwinterz/GitTrace` (public). Its default branch
is **`main`**; the CLI rebuild happens on **`v2`**.

```bash
git status                   # confirm only the files you meant to change
python -m pytest tests/test_core.py tests/test_ingest.py tests/test_rules.py tests/test_scan.py tests/test_llm.py -q

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
