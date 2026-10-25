# GitTrace

**Scan a Python project, find the vulnerabilities an HTTP route can actually reach, and see the attack path, the blast radius and the owner — from a code graph in FalkorDB.**

[![tests](https://github.com/codingwinterz/GitTrace/actions/workflows/tests.yml/badge.svg)](https://github.com/codingwinterz/GitTrace/actions/workflows/tests.yml)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB)
![FalkorDB](https://img.shields.io/badge/graph%20database-FalkorDB-orange)
![license MIT](https://img.shields.io/badge/license-MIT-green)

**Hackathon:** Graph Hacks — Track 01 (Agents That Act on Connected Data) · **Team:** SUDO SAIYAN (Avaneesh S, solo) · Team code `5S3M9E`
**Demo video:** [GIT TRACE's Working & Explanation](https://youtu.be/xwo16Zesdus) (3 min, of the `main` branch)

> **This branch (`v2`) is the command-line rebuild** — see `CLAUDE.md` for the plan. The web UI, HTTP API and the synthetic CVE demo graph shown in the video are on `main` only. Python is the only language supported.

---

## What it does

```bash
python -m gittrace scan path/to/project
```

1. **Reads the real code** with tree-sitter: every function, method and nested function, the calls between them, and the FastAPI / Flask routes with their auth dependencies.
2. **Builds a graph** of it in FalkorDB, one graph per project.
3. **Runs deterministic rules** for SQL built from strings, `eval`/`exec`, shell commands from non-constant input, unsafe deserialization and hardcoded secrets — one finding per dangerous call site.
4. **Asks the graph who can reach each finding**: the shortest path from every endpoint (unauthenticated first), the upstream callers (blast radius), and `git blame` for the owner.
5. **Scores severity deterministically** from the rule, the reachability and the blast radius, and prints it with Rich (or JSON for CI).

Rules detect; nothing else decides what is a finding. The explanation and fix-suggestion layer (a local model through LiteLLM) is a later phase and is not in this branch yet.

## See it work

`tests/fixtures/sample_app` is a small FastAPI app with planted vulnerabilities and planted non-findings. Every value below is asserted by the test suite, offline and against a real FalkorDB:

| Finding | Severity | Why |
|---|---|---|
| `cursor.execute(f"... '{name}'")` in `app/db.py:17` | **critical** (11) | reached from `GET /api/users/{name}` without auth (and from `GET /me` with auth); `name` is a parameter; blast radius 5 |
| `os.system("logger " + msg)` in `app/utils/shell.py:8` | **critical** (10) | `GET /api/users/{name}/files` → `list_files` → `run_command` → `run_command.log`, no auth |
| `os.popen(cmd)` in `app/routers/debug.py:16` | **critical** (10), *uncertain* | the debug router is never included, so its route prefix is not resolved |
| `eval(expr)` in `app/routers/admin.py:11` | **high** (8) | reachable only through the admin router, which requires `Depends(get_current_user)` |
| `"... %s" % days` → `conn.execute` in `app/services/maintenance.py:19` | **medium** (5) | no route reaches it (only the cron job `nightly`) |
| `API_TOKEN = "s3c…"` in `app/auth.py:4` | **medium** (4) | hardcoded secret; not adjusted for reachability |

Not reported, on purpose: constant SQL, a parameterised query, `eval("1 + 1")`, `yaml.load(..., Loader=yaml.SafeLoader)`, secrets read with `os.environ`/`os.getenv`, a `PASSWORD_FIELD = "password"` name, a `"changeme"` placeholder.

---

## Quick start

```bash
git clone https://github.com/codingwinterz/GitTrace && cd GitTrace
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
docker compose up -d falkordb                       # or a FalkorDB Cloud instance
cp .env.example .env                                # FALKORDB_HOST=localhost, FALKORDB_PORT=6379, empty password
python -m gittrace scan tests/fixtures/sample_app
```

Run from the repository root. Until the package is installed with its `gittrace` entry point (a later phase), the CLI is `python -m gittrace`.

### Commands

```bash
python -m gittrace scan <path> [--format rich|json] [--min-severity LEVEL] [--depth N]
                               [--fail-on LEVEL|none] [--offline] [--no-blame] [--include-tests]
python -m gittrace trace <file.py:line | finding-id> [--project PATH] [--depth N] [--format ...]
python -m gittrace blast-radius <function-id> [--project PATH] [--depth N] [--format ...]
```

- `scan` writes the project's graph and prints a headline panel, a findings table (severity, rule, file:line, the endpoint that reaches it, whether that endpoint needs auth), then for each finding the code with the line highlighted, the attack paths as a tree, the blast radius, the owner and the severity reasons.
- `--fail-on` (default `high`) sets the exit code: **1** if any finding is at or above it, so `scan` can gate CI; `none` never fails. `--min-severity` only filters what is shown.
- `--depth` (default 10, max 50) bounds the CALLS hops followed from a route handler to the vulnerable function, and the upstream callers counted in the blast radius.
- `--offline` computes reachability in memory and writes nothing to FalkorDB (same rules and scores); `trace` and `blast-radius` need the graph.
- `--no-blame` skips `git blame`. Outside a git repository the owner lookup is skipped quietly.
- Findings in test code (a `tests`/`test` directory, `test_*.py`, `*_test.py`, `conftest.py`) are listed in a separate section at `info` and never trip `--fail-on`; `--include-tests` treats them like any other code.
- Exit code **2** means an error: bad arguments, an unscanned project, FalkorDB unreachable.

### Environment

| Variable | Required | Purpose |
|---|---|---|
| `FALKORDB_HOST` / `FALKORDB_PORT` | yes (not with `--offline`) | FalkorDB instance |
| `FALKORDB_USER` / `FALKORDB_PASSWORD` | cloud only | Instance credentials |
| `Gemini_API_Key`, `LITELLM_MODEL` | no | Only for the experimental agent loop (`gittrace.core.agent`) |

`.env` is gitignored.

---

## Rules

Each rule is its own module under `gittrace/rules/`, with its id, what it matches and what it deliberately does not match in the module docstring. Rules see only language-neutral facts (a call's full callee name and a description of each argument), never a syntax tree, so another language plug-in can reuse them by producing the same facts.

| Rule | Base | Matches | Does not match |
|---|---|---|---|
| `GT-SQLI-001` SQL built from strings | high | `execute`/`executemany`/`executescript`/`mogrify`/`raw`/`read_sql[_query]` on any receiver, `sqlalchemy.text`, Django `RawSQL`, when the query is an f-string with a non-constant placeholder, `+`, `%`, `.format()` or `.join()` on a string, or a local variable assigned or `+=`-ed from one | constant SQL (including f-strings of constants, class constants, `Model.__tablename__`, and loops over constant tuples), bound parameters, a query passed in unchanged as a parameter, a query returned by another function |
| `GT-EVAL-001` dynamic code evaluation | high | the builtins `eval`, `exec`, `compile` on a non-constant argument | constants; `re.compile` and other same-named functions |
| `GT-CMDI-001` shell command injection | high | `subprocess.run/call/check_call/check_output/Popen` with `shell=True` and a non-constant command; `os.system`, `os.popen`, `subprocess.getoutput/getstatusoutput`, `asyncio.create_subprocess_shell` with a non-constant command | argument lists without `shell=True`; constant commands |
| `GT-DESER-001` unsafe deserialization | high | `pickle`/`cPickle`/`dill`/`marshal` `load(s)`, `pandas.read_pickle`, `yaml.load[_all]` without `SafeLoader`/`CSafeLoader`, `yaml.unsafe_load` | `yaml.safe_load`, constant data |
| `GT-SECRET-001` hardcoded secret | medium | a string constant bound to a name, attribute or string subscript (`config["SECRET_KEY"]`) whose last word is key/secret/password/passwd/pwd/pass/token (or `apikey`, `accesstoken`, ...) | env/config lookups, descriptor names (`PASSWORD_FIELD`, `TOKEN_URL`, `API_KEY_HEADER`), non-secret keys (`primary_key`, `sort_key`, `public_key`, `next_token`, `ctx_key`), placeholders, sentences, `ENV_VAR_NAMES`, dunder names, URLs and paths, values under 4 characters; for `*key`/`*token` names, letters-only dotted/kebab/snake identifiers (i18n and cache keys), and for a bare `key`/`token`, values with fewer than two of lower case, upper case and digits |

Every finding records whether its dangerous value **derives from a function parameter**, following local assignments (`q = "..." + x`), augmented assignments, `for`/`with` bindings, and enclosing functions' parameters for closures. Values are not followed across function calls. Calls resolved to project code are never sinks: what is dangerous happens inside them, where the rules look. A hardcoded secret's value is masked in every report.

## Severity

Deterministic: the same code and graph always give the same severity, and each finding lists the reasons that produced its score (`gittrace/core/severity.py`).

| Step | Points |
|---|---|
| Base severity of the rule | critical 8 · high 6 · medium 4 · low 2 · info 0 |
| Reachable from an **unauthenticated** endpoint | +3 |
| otherwise reachable only from **authenticated** endpoints | +1 |
| otherwise **not reachable** from any endpoint | −2 |
| The dangerous value derives from a function parameter | +1 |
| Blast radius (upstream callers + endpoints that reach it) ≥ 5 | +1 |

**Level:** score ≥ 9 critical · 7–8 high · 4–6 medium · 2–3 low · ≤ 1 info.

The reachability and parameter steps apply to flow-sensitive rules only; a hardcoded secret is exposed by the repository, not by a route, so it keeps its base severity. Routes with `prefix_resolved: false` (a router that is never mounted, or a prefix built from a variable) count as reachable, and a finding is flagged **uncertain** when every endpoint that decided its reachability step is one of those.

## Why a graph database?

A scan could compute everything in memory (`--offline` does), so FalkorDB has to earn its place:

- **Persistence across commands.** `scan` writes the project's graph once; `trace`, `blast-radius` and the MCP tools then answer from it without re-parsing the code, and a re-scan updates it in place.
- **Querying from outside the CLI.** The findings, call graph and routes are plain nodes and edges, so they can be explored with Cypher (e.g. in the FalkorDB Browser) or by an agent over MCP, for questions the CLI does not ask.
- **Scaling beyond memory.** Bounded variable-length traversal and native `shortestPath` run in the database, so the call graph of a large codebase does not have to fit in, or be walked by, the Python process.

## Reachability and blast radius

For the function F that contains a finding, with depth D:

```cypher
// upstream callers: the blast radius
MATCH (c:Function)-[:CALLS*1..D]->(f:Function {id: $id})
WHERE c.id <> $id
RETURN DISTINCT c.id ORDER BY c.id

// routes: endpoints whose handler is F or a caller, with one shortest path each
MATCH (f:Function {id: $id})
OPTIONAL MATCH (c:Function)-[:CALLS*1..D]->(f)
WITH f, collect(DISTINCT c) + [f] AS handlers
UNWIND handlers AS h
MATCH (e:Endpoint)-[:HANDLED_BY]->(h)
WITH DISTINCT e, f
WITH e, shortestPath((e)-[:HANDLED_BY|CALLS*1..D+1]->(f)) AS p
WHERE p IS NOT NULL
RETURN e.id, e.method, e.path, e.auth_required, e.prefix_resolved, [n IN nodes(p) | n.id]
```

The first query narrows the candidate endpoints, so FalkorDB's native `shortestPath` only runs for endpoints that can reach F. Routes are reported unauthenticated first, then by hops. The same computation runs in memory for `--offline`; the test suites check both give identical findings.

## Graph model

One graph per project, `gittrace_<folder>_<8 hex of the absolute path>`, rebuilt by every scan: each node and edge is written with `MERGE` on a stable ID and stamped with the scan, and whatever an older scan wrote and this one did not is deleted. Re-scanning unchanged code leaves the graph identical.

| Node | Key properties |
|---|---|
| `(:Project)` | `id` (graph name), `name`, `root`, `scanned_at`, counts, `findings`, `findings_<level>` |
| `(:File)` | `path`, `language`, `sha256`, `lines` |
| `(:Function {resolved: true})` | `id` = `relative/path.py::QualifiedName` (e.g. `app/db.py::Repo.get_user`), `kind` (`function`/`method`/`nested`/`module`), `start_line`, `end_line`, `source`, `is_async` |
| `(:Function {resolved: false})` | `id` = `external::<dotted name>` (e.g. `external::subprocess.run`, aliases expanded), `origin` (`builtin`/`import`/`project`/`unknown`) — one node per name, shared by every call site |
| `(:Endpoint)` | `id` = `METHOD path -> handler`, `framework`, `method`, `path`, `auth_required`, `auth_evidence`, `prefix_resolved` |
| `(:Sink)` | `id` = `path.py::line::col` — one per finding: `rule_id`, `severity`, `score`, `reasons`, `snippet`, `callee`, `evidence`, `params`, `endpoints`, `blast_radius`, `uncertain`, `owner_*` |

Edges: `(File)-[:DECLARES]->(Function|Endpoint)`, `(Endpoint)-[:HANDLED_BY]->(Function)`, `(Function)-[:CALLS {lines}]->(Function)`, `(Function)-[:REACHES_SINK]->(Sink)`. Code that runs at import time (module-level calls, decorators, default arguments) belongs to a `path.py::<module>` function. Indexes on `Function.id`, `File.path`, `Endpoint.id`, `Sink.id`.

### What ingestion resolves

- **Files:** every `.py` file except `.git`, virtualenvs (`venv`, `.venv`, or any directory with a `pyvenv.cfg`), `node_modules`, `__pycache__`, `site-packages`, `build`, `dist`, tool caches, and whatever the project's `.gitignore` files exclude. A file with a syntax error is logged, counted and skipped.
- **Calls, best effort:** same-file and nested functions, `import x [as z]`, `from x import y [as z]`, relative imports, package re-exports, star imports, `self.m()` / `cls.m()` / `super().m()` through project base classes, `Cls().m()`, and variables assigned once from a project class (`repo = Repo(); repo.get()`). Never by bare name. Parameters, attributes (`self.db.execute`) and return values are not type-inferred.
- **Routes:** FastAPI (`@app.get/post/...`, `api_route`, `websocket`, `APIRouter`, `include_router` prefixes, nested routers, `app.mount("/api/v1", api)`) and Flask (`@app.route(methods=...)`, `@bp.get/...`, `Blueprint(url_prefix=...)`, `register_blueprint(url_prefix=...)`). `auth_required` needs obvious evidence: an auth-named `Depends(...)` (also through an alias like `CurrentUser = Annotated[User, Depends(get_current_user)]`), any `Security(...)`, or a decorator such as `@login_required`.

## Graph tools and the MCP server (Track 01)

Four tools read a scanned project's graph; they are declared once in `TOOL_REGISTRY` (`gittrace/core/registry.py`), which drives both the MCP server and the agent loop:

| Tool | Answers |
|---|---|
| `list_findings(project, min_severity, rule_id)` | the last scan's findings, most severe first |
| `trace_attack_path(project, finding, depth)` | shortest routes from endpoints to a finding (`file.py:line` or `path.py::line::col`) |
| `blast_radius(project, function_id, depth)` | callers of a function and the endpoints that reach it |
| `finding_owner(project, finding)` | author, email and commit of the finding's line (`git blame`) |

```bash
python -m gittrace.mcp_server      # stdio transport, from the repository root
```

```json
{ "command": "python", "args": ["-m", "gittrace.mcp_server"], "env": { "PYTHONPATH": "/path/to/GitTrace" } }
```

The MCP tools are named `list_findings_tool`, `trace_attack_path_tool`, `blast_radius_tool` and `finding_owner_tool`.

---

## Tests

```bash
python -m pytest tests/test_core.py tests/test_ingest.py tests/test_rules.py tests/test_scan.py -q   # no DB

docker compose up -d falkordb
FALKORDB_HOST=localhost FALKORDB_PORT=6379 FALKORDB_PASSWORD= \
  python -m pytest tests/test_ingest_integration.py tests/test_scan_integration.py -q
```

- The expected functions, calls and endpoints of `tests/fixtures/sample_app` are written out by hand in `tests/expected_sample_app.py`, and its expected findings, severities, routes and blast radii in `tests/expected_findings.py`. The offline suites check the parser, the rules and the in-memory scan against them; the integration suites check the same facts in a real FalkorDB graph (Sink nodes, `REACHES_SINK` edges, stored severities, every tool's Cypher) and that both reachability backends agree.
- `tests/snapshots/sample_app_scan.json` is a reviewed snapshot of `scan --format json`; a test also checks it against the hand-written expectations. Regenerate with `GITTRACE_UPDATE_SNAPSHOTS=1 pytest tests/test_scan.py -k snapshot` and review the diff.
- CI (`.github/workflows/tests.yml`) runs the offline suites on Python 3.11–3.13 and the integration suites against a FalkorDB service container; locally the integration suites skip when FalkorDB is unreachable.

## Evaluation

`eval/` holds a reproducible evaluation (`python eval/run_eval.py`, see `eval/README.md`). For each deliberately vulnerable app, a ground truth was written from the project's docs and code **before** either tool was run on it. Bandit 1.9.4 is compared **only in the same five categories**. Every finding on the real-world projects was reviewed by hand; per-finding results and reasons are in `eval/results/<label>/` and `eval/<project>/review.json`.

**Sample size is small:** 36 ground-truth vulnerabilities in 5 targets (31 in the four tuning targets, 5 held out), and 3 real-world projects. Treat the percentages as indicative, not as benchmarks.

### 1. Untouched (rules as committed in Phase 4)

| Target | Ground truth | GitTrace TP / FP / FN | Precision · recall | Bandit TP / FP / FN | Precision · recall |
|---|---|---|---|---|---|
| vulpy `bad/` | 5 | 3 / 2 / 2 | 60% · 60% | 5 / 2 / 0 | 71% · 100% |
| vulpy `good/` | 5 | 2 / 0 / 3 | 100% · 40% | 4 / 0 / 1 | 100% · 80% |
| we45 Vulnerable-Flask-App | 6 | 3 / 0 / 3 | 100% · 50% | 6 / 1 / 0 | 86% · 100% |
| Contrast vulnpy | 15 | 15 / 1 / 0 | 94% · 100% | 10 / 2 / 5 | 83% · 67% |
| **Overall** | **31** | **23 / 3 / 8** | **88% · 74%** | **25 / 5 / 6** | **83% · 81%** |
| CTFd (Flask), reviewed | — | 10 findings, 10 false positives (100%) | | | |
| mealie (FastAPI), reviewed | — | 65 findings, 63 false positives (97%) | | | |

### 2. After tuning (eight rule fixes chosen from the misses above, re-run on the same targets)

| Target | Ground truth | GitTrace TP / FP / FN | Precision · recall | Bandit TP / FP / FN | Precision · recall |
|---|---|---|---|---|---|
| vulpy `bad/` | 5 | 5 / 1 / 0 | 83% · 100% | 5 / 2 / 0 | 71% · 100% |
| vulpy `good/` | 5 | 5 / 0 / 0 | 100% · 100% | 4 / 0 / 1 | 100% · 80% |
| we45 Vulnerable-Flask-App | 6 | 4 / 0 / 2 | 100% · 67% | 6 / 1 / 0 | 86% · 100% |
| Contrast vulnpy | 15 | 15 / 0 / 0 | 100% · 100% | 10 / 2 / 5 | 83% · 67% |
| **Overall** | **31** | **29 / 1 / 2** | **97% · 94%** | **25 / 5 / 6** | **83% · 81%** |
| CTFd (Flask), reviewed | — | 3 findings, 3 false positives (100%); 16 more in test code at info | | | |
| mealie (FastAPI), reviewed | — | 15 findings, 13 false positives (87%); 11 more in test code at info | | | |

These numbers are **optimistic by construction**: the fixes were chosen by looking at these same targets. One fix also introduced a new false positive (a dummy `SECRET_KEY` in CTFd's `TestingConfig`).

### 3. Held out (two new targets, chosen after the fixes were final, run once, nothing changed afterwards)

| Target | Ground truth | GitTrace TP / FP / FN | Precision · recall | Bandit TP / FP / FN | Precision · recall |
|---|---|---|---|---|---|
| DVGA (Damn Vulnerable GraphQL App, Flask) | 5 | 4 / 0 / 1 | 100% · 80% | 4 / 1 / 1 | 80% · 80% |
| open-webui (FastAPI), reviewed | — | 29 findings, 27 false positives (93%) | | | |

- DVGA: GitTrace's miss is a seeded password passed as a keyword argument (`User(password="password123")`, not checked); Bandit's miss is the SQL injection through SQLAlchemy `text("..." % ...)`.
- open-webui: the 2 true positives are `exec()` of user-submitted Tool and Function code (code execution by design, permission-gated). The 27 false positives are SQL f-strings that interpolate bind-parameter names, table/column/index names and configuration values, and one default password used only with authentication turned off.

### What the numbers say

- **Within these five categories GitTrace is comparable to Bandit, not better.** Untouched it was 88%/74% against Bandit's 83%/81%; on the held-out vulnerable app both found 4 of 5. The after-tuning gap is not evidence, because the tuning saw those targets.
- **GitTrace's contribution is the context around a finding**: whether a route reaches it and whether that route needs authentication, the path, the blast radius over callers and endpoints, and the owner from `git blame`. On the vulnerable apps, 7 of the 23 untouched true positives were marked reachable without auth, and 1 of the 4 held-out ones.
- **That context is only as good as route and auth detection.** On the held-out DVGA, the one "reachable without auth" finding (`run_cmd`) is reached through `/start_over`, which passes a constant command, while the real attack paths go through `/graphql` (graphene dispatch, not visible statically). On open-webui, all 9 findings marked unauthenticated and critical are behind `Depends(get_verified_user)`, whose name the auth check does not recognise, so their severity is overstated.
- **Real-world precision is low.** Most reported patterns are real but harmless (SQL built from trusted identifiers). On CTFd and mealie every finding is `medium`, so `--min-severity high` hides all their false positives, but it also hides mealie's two true positives. On open-webui it would not help: the auth miss above put 7 false positives at `critical`.

## Limitations

- **Python only**, and only FastAPI and Flask routes.
- **Intraprocedural data flow.** A dangerous value is tracked through assignments inside one function (and closures), not across calls, and a query passed in unchanged as a parameter is not a finding.
- **Known false negative: SQL built in another function.** When one function builds the SQL string and another executes it, nothing is reported:

  ```python
  def delete_user(self, user_id):
      def build_query():
          return "DELETE FROM users WHERE id = " + str(user_id)
      self.conn.execute(build_query())   # not reported: the argument is a call result
  ```

  This exact case is in `tests/fixtures/sample_app/app/db.py:24`, and the tests assert that it is *not* reported, so a fix will show up as a deliberate test change.
- **Call resolution is static and conservative.** Calls on parameters, attributes or return values (`db_session.query`, `self.repo.get`) stay unresolved, so paths through them are missed; dynamic dispatch (plugin registries, `getattr`) is invisible.
- **Rules are pattern rules.** A finding means the dangerous pattern is there, not that it is exploitable: a query formatted from trusted schema names is still reported, with a lower severity when no route reaches it.
- **Auth detection is name-based** and only sees obvious dependencies and decorators; checks inside the handler body (e.g. signature verification) are not recognised, and names outside the pattern (open-webui's `get_verified_user`) make an authenticated route look unauthenticated.
- **Secrets are only checked where they are bound to a name**, an attribute or a string subscript; a password passed as a keyword argument (`User(password="...")`) or held in a dict literal is not reported.
- **The model layer is not built yet.** Explanations and fix diffs come in a later phase; the agent loop in `gittrace.core.agent` is a generic, experimental shell.

## AI assistance disclosure (Rule 11)

This project was built with AI coding assistance. An AI coding agent (Codebuff) wrote and edited code, tests, and documentation in this repository under the author's direction; the author ran the application, verified the graph queries against the live FalkorDB instance, and validated the outputs quoted in this README. No result in this document is a model claim — each one was produced by executing the code in this repo. The `v2` command-line rebuild is being written with Claude Code under the author's direction, phase by phase.

## License

MIT — see [LICENSE](LICENSE).
