# Run GitTrace locally

One-page, clone-to-run companion to README.md. For a full description, architecture,
Cypher queries, and the MCP server, see README.md.

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
  - "What's the shortest path from api-gateway to validate_token?"
  - "Who owns validate_token?"
- Backend API: `python app.py` → `http://localhost:8000`
  - `GET  /health`
  - `POST /query`  (natural-language security question)
  - `GET  /tools`  (tool schemas)
  - `GET  /demo`   (scripted demo scenario)

## Env vars

See `.env.example`. The only required ones are the FalkorDB Cloud credentials and the
Gemini API key. Never commit `.env`.

## Tests

```bash
python -m pytest test_app.py test_integration.py -v
```

`test_app.py` is fully mocked (no live DB, no API key needed). `test_integration.py`
hits the live FalkorDB + Gemini + MCP setup, so it needs `.env`.

## MCP server (Track 01)

```bash
python mcp_server.py
```

Stdio transport. Register in your MCP host as:
`{ "command": "python", "args": ["mcp_server.py"] }`.
