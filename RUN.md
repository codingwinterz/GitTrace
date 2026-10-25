# Run GitTrace locally

One-page, clone-to-run companion to README.md. For a full description, architecture,
Cypher queries, and the MCP server, see README.md. Demo video (of the `main` branch,
which still has the web UI): <https://youtu.be/xwo16Zesdus>.

## Fastest start

Run every command from the repository root.

```bash
cp .env.example .env
# Edit .env: set FALKORDB_HOST/PORT/USER/PASSWORD (+ Gemini_API_Key, optional)

pip install -r requirements.txt
python -m gittrace.graph.seed     # one-time graph seed
python -m gittrace.mcp_server     # MCP server on stdio
```

For a local FalkorDB instead of the cloud:

```bash
docker compose up -d falkordb
# .env: FALKORDB_HOST=localhost, FALKORDB_PORT=6379, FALKORDB_PASSWORD= (empty)
```

## What to try

Call the tools from an MCP host, or from Python:

```python
from gittrace.core.agent import run_agent
print(run_agent("What's the blast radius of CVE-2026-4421?").answer)
print(run_agent("Who owns validate_token for CVE-2026-4421?").answer)
```

`validate_token` is defined in two services, so without the CVE (or a file path) the
tools answer that the name is ambiguous and list both candidates.

## Env vars

See `.env.example`. FalkorDB settings are required; `Gemini_API_Key` is optional —
without it the agent falls back to its keyword classifier. Never commit `.env`.

## Tests

```bash
python -m pytest tests -v
```

`tests/test_core.py` is fully mocked (no live DB, no API key needed).
`tests/test_integration.py` runs every Cypher query against a real FalkorDB: it seeds
its own uniquely named graph (`gittrace_test_<random>`), tests against it and drops it,
so it never touches the demo graph. Start a local FalkorDB with Docker and point the
tests at it:

```bash
docker compose up -d falkordb
FALKORDB_HOST=localhost FALKORDB_PORT=6379 FALKORDB_PASSWORD= python -m pytest tests/test_integration.py -v
```

(Environment variables win over `.env`, so this works even with cloud settings in `.env`.)
Without a reachable FalkorDB the integration tests skip. CI runs them against a FalkorDB
service container and sets `GITTRACE_REQUIRE_FALKORDB=1`, which turns that skip into a
failure. The live-LLM test also needs a Gemini key and skips without one.

Run at least the offline suite before pushing. CI (`.github/workflows/tests.yml`) runs
it on Python 3.11–3.13, plus the integration suite against FalkorDB in Docker:

```bash
python -m pytest tests/test_core.py -q
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
python -m pytest tests/test_core.py -q

git add gittrace tests README.md RUN.md
git commit -m "Describe the why, not the what"
git push origin v2
```

Then confirm it actually landed:

```bash
git log --oneline -1 origin/v2
```

### Before every push: no secrets

`.env` is gitignored and must stay that way — it holds the FalkorDB password and the
Gemini API key. Check the tracked tree, not just the working directory:

```bash
git ls-files | grep -i '\.env$'          # must print nothing
git grep -nE 'AIza[0-9A-Za-z_-]{10,}|AQ\.[A-Za-z0-9_-]{10,}'   # must print nothing
```

If a key ever does get committed, rotate it in FalkorDB Cloud / AI Studio first — a
force-push does not un-leak it — then rewrite history.

Do not commit `*.log`, `debug/`, `.venv/`, `__pycache__/`, or `.pytest_cache/`; all are
already in `.gitignore`.
