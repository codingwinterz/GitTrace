# Run GitTrace locally

One-page, clone-to-run companion to README.md. For a full description, architecture,
Cypher queries, and the MCP server, see README.md. Demo video:
<https://youtu.be/xwo16Zesdus>.

## Fastest start (judge/teammate friendly)

```bash
cp .env.example .env
# Edit .env: set FALKORDB_HOST/PORT/USER/PASSWORD + Gemini_API_Key

pip install -r requirements.txt
python seed_graph.py     # one-time graph seed
python app.py            # backend on :8000
```

Then in another terminal:

```bash
python -m http.server 5500 --directory frontend
# open http://localhost:5500
```

Or use VS Code Live Server on port 5500.

## What to demo

- Open http://localhost:5500 and click **Run demo**, or ask:
  - "What's the blast radius of CVE-2026-4421?"
  - "What's the shortest path from api-gateway to validate_token for CVE-2026-4421?"
  - "Who owns validate_token for CVE-2026-4421?"

  `validate_token` is defined in two services, so without the CVE (or a file
  path) the tools answer that the name is ambiguous and list both candidates.
- Backend API: `python app.py` → `http://localhost:8000`
  - `GET  /`        (root health check)
  - `GET  /health`
  - `POST /query`  (natural-language security question)
  - `GET  /tools`  (tool schemas)
  - `GET  /demo`   (scripted demo scenario)

## Env vars

See `.env.example`. The FalkorDB Cloud credentials are required; `Gemini_API_Key` is
optional — without it the agent falls back to its keyword classifier and the demo still
works end to end. Never commit `.env`.

## Tests

```bash
python -m pytest test_app.py test_integration.py -v
```

`test_app.py` is fully mocked (no live DB, no API key needed). `test_integration.py`
runs every Cypher query against a real FalkorDB: it seeds its own uniquely named graph
(`gittrace_test_<random>`), tests against it and drops it, so it never touches the demo
graph. Start a local FalkorDB with Docker and point the tests at it:

```bash
docker compose up -d falkordb
FALKORDB_HOST=localhost FALKORDB_PORT=6379 FALKORDB_PASSWORD= python -m pytest test_integration.py -v
```

(Environment variables win over `.env`, so this works even with cloud settings in `.env`.)
Without a reachable FalkorDB the integration tests skip. CI runs them against a FalkorDB
service container and sets `GITTRACE_REQUIRE_FALKORDB=1`, which turns that skip into a
failure. The live-LLM test also needs a Gemini key and skips without one.

Run at least the offline suite before pushing. CI (`.github/workflows/tests.yml`) runs
it on Python 3.11–3.13, plus the integration suite against FalkorDB in Docker:

```bash
python -m pytest test_app.py -q
```

## MCP server (Track 01)

```bash
python mcp_server.py
```

Stdio transport. Register in your MCP host as:
`{ "command": "python", "args": ["mcp_server.py"] }`.

## Pushing changes to GitHub

The repo is `https://github.com/codingwinterz/GitTrace` (public) and its default
branch is **`main`**. Work locally on `main` so pushes land where visitors look.

```bash
git switch main              # create from your work if it does not exist yet
git status                   # confirm only the files you meant to change
python -m pytest test_app.py -q

git add app.py seed_graph.py frontend test_app.py README.md RUN.md
git commit -m "Describe the why, not the what"
git push origin main
```

Then confirm it actually landed:

```bash
gh repo view codingwinterz/GitTrace --json defaultBranchRef,visibility
git log --oneline -1 origin/main
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
