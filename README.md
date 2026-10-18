# GitTrace

**CVE blast-radius agent over FalkorDB.**

Given a security vulnerability alert (CVE) in a codebase, GitTrace uses FalkorDB graph
traversal to answer three questions:

1. **Blast radius** — which services and functions are impacted, and how does the
   vulnerability propagate?
2. **Shortest attack path** — from a public entry point to the vulnerable code, how
   many hops and through what path?
3. **Code owner** — who owns the affected code and needs to be alerted?

**Stack:** Python (FastAPI) + FalkorDB Cloud + LiteLLM (Gemini) + static frontend.

**Hackathon:** Graph Hacks — Track 01 (Agents That Act on Connected Data).
Team: **SUDO SAIYAN** (Avaneesh S, solo). Team code: `5S3M9E`.

---

## Why FalkorDB (Rule 3)

A vector database can't run native graph algorithms or do multi-hop structural traversal.
GitTrace depends on two native graph capabilities that only a graph DB provides:

- **Multi-hop traversal** — `[:CALLS*1..5]` propagation from the vulnerable function to
  downstream functions and the services that contain them.
- **Native shortestPath** — FalkorDB's `shortestPath()` algorithm traces the exact attack
  path from a public-facing service to the vulnerable function.

Removing FalkorDB breaks the product. This is the core of the submission.

---

## Project structure

```
gittrace/
├── seed_graph.py             # Seeds FalkorDB with the graph schema + mock data
├── app.py                    # FastAPI backend + LLM agent loop (3 graph tools)
├── mcp_server.py             # MCP server exposing the 3 graph tools (Track 01)
├── utils.py                  # Shared FalkorDB connection helpers
├── requirements.txt          # Python dependencies
├── .env.example              # Template for credentials (copy to .env; never commit .env)
.github/                       # GitHub repo metadata (present after first push)
LICENSE                        # MIT — see below
├── README.md                 # This file — setup, graph model, Cypher, demo, winning-criteria coverage
├── RUN.md                    # One-page clone→run companion for judges/teammates
├── SPEC.md                   # Hackathon spec: schema, tools, demo script, build phases, submission checklist
├── test_app.py               # Unit tests (mocked graph + mocked LLM): helpers, tools, agent, endpoints
├── test_integration.py       # Live tests: FalkorDB Cloud + Gemini + MCP end-to-end
├── verify_contracts.py       # Asserts /demo and /query response shapes match spec
├── verify_graph_outputs.py   # Asserts live FalkorDB results for the demo scenario
└── frontend/
    ├── index.html            # Chat UI + Run demo button + graph panel
    ├── app.js                # Frontend logic + SVG attack-path visualization
    └── style.css             # Styles
```

---

## MCP server (Track 01 requirement)

GitTrace ships a real [Model Context Protocol](https://modelcontextprotocol.io) server,
`mcp_server.py`, exposing the three FalkorDB graph tools so any MCP-capable agent host
(Claude Desktop, custom agents, etc.) can query the dependency graph:

```bash
python mcp_server.py    # stdio transport
```

Register in your MCP host:

```json
{ "command": "python", "args": ["mcp_server.py"] }
```

Tools exposed: `get_blast_radius_tool`, `find_shortest_dependency_path_tool`,
`find_code_owner_tool`. Verified by `test_integration.py::TestLiveMCP`.

---

## Tests

```bash
python -m pytest test_app.py test_integration.py -v
```

- **`test_app.py`** (34 tests) — helper functions, all 3 graph tools (mocked graph), the
  keyword classifier, the full LiteLLM agent loop (mocked LLM, covering success and every
  fallback path), and the FastAPI endpoints. No DB or API key needed.
- **`test_integration.py`** (7 tests) — live tests against the real FalkorDB Cloud
  instance, the live Gemini agent loop, and an end-to-end MCP tool call. These skip
  automatically when FalkorDB is unreachable.

---

## Quick start

### 1. FalkorDB Cloud

1. Sign up at [app.falkordb.cloud](https://app.falkordb.cloud).
2. Create a **FalkorDB Free** deployment instance (Google Cloud, `us-central1` is fine).
3. Open the instance → **Connectivity** → **Connect** and copy the host, port, user, and
   password (or connection string).
4. Open FalkorDB Browser from the Connect panel and keep the tab open — the frontend
   embeds it.

### 2. Install dependencies

```bash
cd gittrace
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Configure credentials

Copy the template and fill in the real values:

```bash
cp .env.example .env
```

Edit `.env`:

```
FALKORDB_HOST=<host from Connect panel>
FALKORDB_PORT=<port from Connect panel>
FALKORDB_USER=falkordb
FALKORDB_PASSWORD=<password from Connect panel>

# Google AI (Gemini) via LiteLLM
Gemini_API_Key=<your Gemini API key>
LITELLM_MODEL=gemini/gemini-flash-lite-latest
```

- `FALKORDB_PASSWORD` and `Gemini_API_Key` must be real values before the app runs.
- `.env` is in `.gitignore` and must not be committed.

### 4. Seed the graph

```bash
python seed_graph.py
```

This creates the `gittrace` graph and seeds:

| Node type | Count |
|-----------|-------|
| Service | 7 |
| File | 7 |
| Function | 22 |
| Developer | 4 |
| CVE | 2 |
| APIEndpoint | 5 |

The seed wires the demo scenario:

- `CVE-2026-4421` (CRITICAL) affects `token-service.validate_token`
- Public entry → `api-gateway` → `token-service` → `token-service/token.py` → `validate_token`
- Code owner: **Sarah Chen** (`sarah.chen@acme.com`, `@sarahc`)

> ⚠️ **Known limitation — duplicate `validate_token` in the seed data.**
>
> The original seed graph defined `validate_token` twice: once in
> `auth-service/auth.go` and once in `token-service/token.py`. Because
> `find_shortest_dependency_path` matched functions by name alone, it could
> resolve to the auth-service instance by default — the wrong one for
> CVE-2026-4421, which only affects the token-service copy. That produced a
> misleading 3-hop auth-service path even though `get_blast_radius` correctly
> scoped to the token-service instance via its AFFECTS edge. This was fixed by
> adding optional `cve_id` and `target_file_path` disambiguators to
> `find_shortest_dependency_path` so the tool now resolves CVE-driven path
> queries to the exact affected instance (token-service) the same way
> `get_blast_radius` already does.

### 5. Run the tests

```bash
python -m pytest test_app.py -v
```

The suite covers the helper functions, all three FalkorDB graph tools (mocked, so
no live DB is needed), the keyword-classifier agent, the LiteLLM agent loop (mocked
LLM, so no Gemini API key or quota is consumed), and the FastAPI endpoints.

### 6. Run the backend

```bash
python app.py
```

The API starts on `http://localhost:8000` by default (`GITTRACE_PORT` overrides it).

Endpoints:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `POST` | `/query` | Ask a natural-language security question |
| `GET` | `/tools` | List available graph tools (OpenAI-format tool schemas) |
| `GET` | `/demo` | Run the scripted demo scenario and return all results |

### 7. Run the frontend

Serve the `frontend/` folder from a static server. Examples:

```bash
# Python
python -m http.server 5500 --directory frontend

# or VS Code Live Server on port 5500
```

Open `http://localhost:5500` (or whatever the frontend server reports). The app expects
the backend at `localhost:8000` when served from `localhost:5500`; see `frontend/app.js`
for the `API_BASE` knob if your setup differs.

The frontend embeds FalkorDB Browser via iframe at the graph tab URL from your Connect
panel; set that URL in `.env` (`GITTRACE_FRONTEND_ORIGIN` is mainly for CORS on the
_API_, not the iframe).

---

## First-time setup (clone → run in 60 seconds)

This is the fastest path for a judge or teammate cloning the repo:

```bash
# 1. Env from the template (never commit .env)
cp .env.example .env

# 2. Fill in the four real values in .env:
#    FALKORDB_HOST, FALKORDB_PORT, FALKORDB_USER, FALKORDB_PASSWORD,
#    Gemini_API_Key

# 3. Install deps
pip install -r requirements.txt

# 4. Seed the graph (one time)
python seed_graph.py

# 5. Start the backend
python app.py

# 6. Open the frontend
python -m http.server 5500 --directory frontend
# then open http://localhost:5500
```

If you don't have a FalkorDB instance yet, the backend still starts; only the graph-
dependent endpoints (`/query`, `/demo`) will fail until the instance is wired up.

---

## Graph model

```bash
# Python
python -m http.server 5500 --directory frontend

# or VS Code Live Server on port 5500
```

Open `http://localhost:5500` (or whatever the frontend server reports). The app expects
the backend at `localhost:8000` when served from `localhost:5500`; see `frontend/app.js`
for the `API_BASE` knob if your setup differs.

The frontend embeds FalkorDB Browser via iframe at the graph tab URL from your Connect
panel. If the embed is blocked by cross-origin policy, the UI shows a fallback link to
open the browser in a new tab.

---

## Graph data model

### Nodes

| Node | Properties |
|------|------------ |
| `(:Service {name, language, port, is_public})` | Microservice name, language, port, whether publicly exposed |
| `(:File {path})` | File path in the repo |
| `(:Function {name, line_number, is_entry_point})` | Function name, line number, whether it's a public API endpoint |
| `(:Developer {name, email, slack_handle})` | Team member info |
| `(:CVE {id, severity, description})` | Vulnerability record |
| `(:APIEndpoint {path, method})` | Public API surface |

### Edges

| Edge | From → To | Meaning |
|------|-----------|---------|
| `CONTAINS` | Service → File | Service contains this file |
| `DEFINES` | File → Function | File defines this function |
| `CALLS` | Function → Function | Function calls another function |
| `DEPENDS_ON` | Service → Service | Service depends on another service |
| `OWNS` | Developer → Service | Developer owns this service |
| `AUTHORED` | Developer → File | Developer authored this file |
| `AFFECTS` | CVE → Function | CVE affects this function |
| `EXPOSES` | APIEndpoint → Function | API endpoint exposes this function |

---

## Agent tools

The backend exposes three FalkorDB-backed tools that the LLM agent can call.

### `get_blast_radius(cve_id)`

Find all services and functions impacted by a CVE, showing the propagation path.

```cypher
MATCH path = (c:CVE {id: $cve_id})-[:AFFECTS]->(f:Function)
OPTIONAL MATCH affected = (f)-[:CALLS*1..5]->(downstream:Function)
OPTIONAL MATCH downstream_service = (downstream)<-[:DEFINES]-(f2:File)<-[:CONTAINS]-(s:Service)
RETURN
    c.id AS cve_id,
    c.severity AS severity,
    collect(DISTINCT s.name) AS impacted_services,
    collect(DISTINCT downstream.name) AS impacted_functions,
    count(DISTINCT s) AS service_count
```

### `find_shortest_dependency_path(start_service, target_function, *, cve_id=None, target_file_path=None)`

Use FalkorDB's native `shortestPath` to trace how an attacker reaches a **specific**
Function node from a public-facing service. When `cve_id` is supplied the target is
derived from the CVE's `AFFECTS` edge — the same relationship `get_blast_radius` uses —
so both tools are guaranteed to point at the same instance of the code. When
`target_file_path` is supplied the target is the Function defined by that exact file.
Without either, the query falls back to a name-only match (correct only for functions
that exist in a single place; see the known limitation above).

```cypher
MATCH (c:CVE {id: $cve_id})-[:AFFECTS]->(f:Function)
MATCH (s:Service {name: $start_service, is_public: true})
WITH s, f, shortestPath((s)-[:CONTAINS|DEFINES|DEPENDS_ON*1..10]->(f)) AS p
RETURN
    [n IN nodes(p) | labels(n)[0] + ':' + coalesce(n.name, n.path, n.id)] AS path_trace,
    length(p) AS hop_count
ORDER BY hop_count ASC, path_trace ASC
LIMIT 1
```

`ORDER BY` makes the result deterministic when several equal-length paths exist; the
name-only fallback has the same tie-break.

### `find_code_owner(function_name)`

Find the developer who owns/authored the vulnerable code for alerting.

```cypher
MATCH (f:Function {name: $function_name})<-[:DEFINES]-(file:File)<-[:AUTHORED]-(dev:Developer)
OPTIONAL MATCH (dev)-[:OWNS]->(s:Service)
RETURN
    dev.name AS developer_name,
    dev.email AS email,
    dev.slack_handle AS slack,
    collect(DISTINCT s.name) AS owned_services
LIMIT 1
```

---

## Demo scenario

The scripted demo (60-90s) runs from the **Run demo** button in the frontend or from
`GET /demo`:

1. **Blast radius** — "What's the blast radius of CVE-2026-4421?"
2. **Attack path** — "What's the shortest path from api-gateway to validate_token for CVE-2026-4421?"
3. **Code owner** — "Who owns validate_token and how do I contact them?"

Expected results with the seeded graph:

- Blast radius: `CVE-2026-4421`, CRITICAL, impacts `token-service` and downstream
  functions including `validate_token`.
- Attack path: `api-gateway` → `token-service` → `token-service/token.py` → `validate_token`, 3-hop path (CVE-scoped via AFFECTS edge to the affected instance).
- Code owner: Sarah Chen, `sarah.chen@acme.com`, `@sarahc`, also owns `auth-service`
  and `token-service`.

For the demo video, capture the FalkorDB Browser with the red attack path highlighted —
that's the "why we need a graph" moment in §4 of the spec.

---

## LLM / model notes

The agent uses LiteLLM so the model is swappable. Set:

- `LITELLM_MODEL` — e.g. `gemini/gemini-flash-lite-latest` (default) or any LiteLLM-supported model string. We use a Flash-Lite model because free-tier quotas are per-model; when one model's daily quota is exhausted, switching to another Flash-Lite variant keeps the agent live.
- `Gemini_API_Key` (or the relevant provider key) in `.env`.

The backend supports two paths:

1. **Function calling path** — when the model supports tool calls, the agent calls tools
   via LiteLLM, then feeds results back for a final answer.
2. **Keyword classifier fallback** — if LiteLLM isn't configured or fails, the backend
   classifies the question with keyword heuristics and calls the relevant tools directly.
   The demo works through this path even without a valid API key.

---

## Submission checklist

- [ ] Public GitHub repo
- [ ] README with setup instructions (this file)
- [ ] Graph data model documented (§Graph data model)
- [ ] Actual Cypher queries included (§Agent tools)
- [ ] Demo video (working project)
- [ ] Live deployment OR complete local setup
- [ ] Track(s) explicitly named in submission (Track 01)

---

## Winning criteria coverage

| Criterion | How we hit it |
|-----------|---------------|
| Graph is essential (Rule 3) | Multi-hop traversal + native shortestPath — vector DB can't do this |
| MCP or GraphRAG-SDK used | **Real MCP server** (`mcp_server.py`) exposing all 3 graph tools over the Model Context Protocol — runnable via `python mcp_server.py` |
| At least 2 native graph algorithms | shortestPath + multi-hop traversal |
| Explainable results | Demo shows exact path from entry point to vulnerability |
| Visual graph proof | FalkorDB Browser embed + screenshot in demo video |
| Live deployment | Frontend static; backend + graph on FalkorDB Cloud |

---

## Risks & scope

- Keep scope tight: 3 tools, 1 demo scenario, nothing more.
- If the LLM doesn't call tools correctly, the keyword classifier fallback covers the demo.
- FalkorDB Cloud connection issues: test the seed script early; the fallback classifier
  doesn't need the DB for the demo if the graph is already seeded.
- Demo video timing: script it tightly and practice once before recording.

---

*Last updated: Oct 17, 2026*
