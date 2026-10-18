# GitTrace — original build plan

> **Status: historical.** This is the plan written before the build, kept for provenance.
> It is not a description of what shipped — for that, see [README.md](README.md), which
> reflects the code, tests, and demo video as they exist today.

**Team:** SUDO SAIYAN (Avaneesh S, solo)  
**Track:** Track 01 — Agents That Act on Connected Data  
**Prize:** iPhone 18 Pro  
**Stack (planned):** Python + FalkorDB Cloud + static frontend  
**Deadline:** Sunday, Oct 18, 11:59 PM IST

---

## 1. Project Overview

**GitTrace** is an agent that takes a security vulnerability alert (CVE) in a codebase and uses FalkorDB graph traversal to answer:
- Which services are impacted? (blast radius)
- What's the shortest attack path from public entry point to vulnerable code?
- Who owns the affected code and needs to be alerted?

**Core value proposition:** A vector database can't run native graph algorithms or do multi-hop structural traversal. FalkorDB is essential — removing it breaks the product (Rule 3 compliant).

---

## 2. Graph Schema

### Nodes

| Node | Properties |
|------|------------|
| `(:Service {name, language, port, is_public})` | Microservice name, language, port, whether it's publicly exposed |
| `(:File {path})` | File path in the repo |
| `(:Function {name, line_number, is_entry_point})` | Function name, line number, whether it's a public API endpoint |
| `(:Developer {name, email, slack_handle})` | Team member info |
| `(:CVE {id, severity, description})` | Vulnerability record |
| `(:APIEndpoint {path, method})` | Public API surface |

### Relationships

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

## 3. Agent Tools (Python)

### Tool 1: get_blast_radius(cve_id)

**Purpose:** Find all services and functions impacted by a CVE, showing the propagation path.

**Cypher Query:**
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

**Returns:** List of impacted services, functions, and count.

---

### Tool 2: find_shortest_dependency_path(start_service, target_function, *, cve_id=None, target_file_path=None)

**Purpose:** Use FalkorDB's native shortestPath algorithm to trace how an attacker reaches a specific vulnerable function node from a public-facing service. The target is scoped to a single Function *instance* (not any function sharing its name): when `cve_id` is supplied the tool derives the target node from the CVE's AFFECTS edge (the same source `get_blast_radius` uses), and when `target_file_path` is supplied it matches the exact Function defined by that file. Without either, it falls back to a name-only match for functions that only exist in one place.

**Cypher Query (CVE-scoped):**
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

**Returns:** The exact multi-hop path from public service to vulnerable function, with hop count.

---

### Tool 3: find_code_owner(function_name)

**Purpose:** Find the developer who owns/authorized the vulnerable code for alerting.

**Cypher Query:**
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

**Returns:** Developer contact info and owned services.

---

## 4. Demo Scenario (60-90 second video)

| Time | What Happens |
|------|--------------|
| 0:00-0:10 | "A critical CVE was found in validate_token. What breaks if we take it offline?" |
| 0:10-0:25 | Agent calls `get_blast_radius` — shows impacted services list |
| 0:25-0:40 | Agent calls `find_shortest_dependency_path` (CVE-scoped) — shows the 3-hop attack path to token-service:validate_token |
| 0:40-0:55 | Agent calls `find_code_owner` — returns Sarah Chen's contact info |
| 0:55-1:10 | Visual: FalkorDB Browser screenshot with red path highlighted. "This is why we need a graph." |

---

## 5. Tech Stack

| Layer | Technology |
|-------|------------|
| Graph Database | FalkorDB Cloud (free tier) |
| Backend | Python (FastAPI or Flask) |
| Agent Framework | graphrag-sdk or falkordb + LiteLLM/ LangChain |
| LLM | LiteLLM (allows switching between models) |
| Frontend | React or simple HTML/JS on Vercel/Netlify |
| MCP | @falkordb/mcpserver (optional, for Track 1 points) |

---

## 6. Build Phases

### Phase 1: Tonight (5 min)
- [ ] Sign up for FalkorDB Cloud
- [ ] Create instance, get credentials (FALKORDB_HOST, FALKORDB_PASSWORD)
- [ ] Save credentials to `.env` file

### Phase 2: Tomorrow AM — Seed Script
- [ ] Write `seed_graph.py` that connects to FalkorDB Cloud
- [ ] Create the graph schema
- [ ] Seed 5-8 services, ~20 functions, 3-4 developers, 2 CVEs
- [ ] Run test queries to verify data is correct

### Phase 3: Tomorrow PM — Agent Loop
- [ ] Set up Python backend (FastAPI/Flask)
- [ ] Integrate LLM via LiteLLM
- [ ] Wire up the 3 graph tools as function calls
- [ ] Test agent loop: prompt → tool selection → query → response

### Phase 4: Saturday — Frontend + Viz
- [ ] Build simple UI (chat-style interface)
- [ ] Add graph visualization (FalkorDB Browser embed or react-force-graph)
- [ ] Connect frontend to backend

### Phase 5: Sunday AM — Polish
- [ ] Record demo scenario
- [ ] Test end-to-end flows
- [ ] Fix any broken paths

### Phase 6: Sunday PM — Deliverables
- [ ] Record demo video (Loom/OBS, 2-3 min)
- [ ] Write README with setup instructions + graph data model + Cypher queries
- [ ] Write blog post (for AirPods 5 side prize)
- [ ] Deploy frontend to Vercel/Netlify
- [ ] Submit before 8PM IST (deadline 11:59 PM)

---

## 7. Submission Checklist

Tracked live in [README.md](README.md#track-01-and-the-submission-rules); all items are
complete except a public deployment, which rule 10 does not require when complete local
setup is provided.

---

## 8. Winning Criteria Checklist

| Criterion | How We Hit It |
|-----------|---------------|
| Graph is essential (Rule 3) | Multi-hop traversal + shortestPath algorithm — vector DB can't do this |
| MCP or GraphRAG-SDK used | ✅ Real MCP server (`mcp_server.py`) exposing all 3 graph tools, verified by `test_integration.py::TestLiveMCP` |
| At least 2 native graph algorithms | shortestPath + multi-hop traversal (count as 2) |
| Explainable results | Demo shows exact path from entry point to vulnerability |
| Visual graph proof | FalkorDB Browser screenshot in demo video |
| Live deployment | Local setup: backend + FalkorDB Cloud, frontend served statically |

---

## 9. Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| LLM doesn't call tools correctly | Use structured tool calling, have fallback to direct Cypher |
| FalkorDB Cloud connection issues | Test early, have local fallback plan |
| Demo video time overrun | Script it tightly, practice once before recording |
| Can't explain the graph under questioning | Keep schema simple, know every query by heart |
| Scope creep | Stick to 3 tools, 1 demo scenario — nothing more |

---

## 10. Files to Create

```
gittrace/
├── seed_graph.py          # Seeds FalkorDB with mock data
├── app.py                 # FastAPI backend + agent loop
├── requirements.txt       # Python dependencies
├── .env                   # FalkorDB credentials (gitignored)
├── .gitignore             # Include .env
├── README.md              # Setup instructions + graph model + Cypher queries
├── frontend/              # React or static HTML
│   ├── index.html
│   ├── app.js
│   └── style.css
├── demo/                  # Demo assets
│   └── demo-video.mp4
└── blog/                  # Blog post (optional, for AirPods 5)
    └── post.md
```

---

## Conversation Notes

- Started: Oct 16, planning for Graph Hacks hackathon (FalkorDB-powered)
- Team registered as "SUDO SAIYAN" with team code 5S3M9E
- 7,499 registered participants — ~60% won't submit, ~30% submit half-broken projects
- Realistic shot at winning if we execute cleanly
- Key: keep scope tight, graph must be essential, demo video is priority #1

---

*Last updated: Oct 16, 2026*
