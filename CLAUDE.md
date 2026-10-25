# GitTrace v2 — Project Plan

## Goal
GitTrace is a CLI tool that scans any Python project folder, builds a code 
graph in FalkorDB from the real code, finds vulnerabilities that are actually 
reachable from public API routes, measures their blast radius, and explains 
findings and code in plain language using a local LLM.

## Two commands
- `gittrace scan <path>`: rule-based vulnerability detection, severity at the 
  exact file and line, attack path (route -> sink) and blast radius shown as 
  graphs in the terminal, plus a model-written explanation and suggested fix.
- `gittrace explain <path>`: plain-language summary of each file and function, 
  plus a working-flow graph of how requests move through the code. Aimed at 
  people who built projects with AI and don't understand them.

## Core design rules (do not violate)
1. Rules detect, the model explains. Vulnerability detection is deterministic 
   pattern/rule based. The LLM only explains, adjusts severity with reasoning, 
   and suggests fixes for findings the rules already produced.
2. Suggested fixes are shown as diffs only. Never auto-apply changes to the 
   user's code.
3. Every function node has a stable ID: `relative/path.py::QualifiedName` 
   (e.g. `app/db.py::Repo.get_user`), plus start_line, end_line, and source 
   code. Never match functions by bare name or substring.
4. Use MERGE with stable IDs for all graph writes, so re-scanning is idempotent.
5. Language support is a plug-in: each language provides a parser, a rule set, 
   and a route detector behind a common interface. Python is the only language 
   for now. Use tree-sitter for parsing so other languages can be added later.
6. The graph schema is language-neutral:
   Nodes: Project, File, Function, Endpoint, Sink
   Edges: (File)-[:DECLARES]->(Function|Endpoint), 
          (Endpoint)-[:HANDLED_BY]->(Function),
          (Function)-[:CALLS]->(Function), 
          (Function)-[:REACHES_SINK]->(Sink)
   Unresolved calls (e.g. subprocess.run, cursor.execute) must still become 
   nodes, because those are the sinks.
7. The model layer is pluggable through LiteLLM. Default: a local model via 
   Ollama (configurable, e.g. ollama/qwen2.5-coder:7b or ollama/llama3.1:8b). 
   Set num_ctx to 8192. Send one function at a time with its source, callers, 
   and attack path. Require JSON output, validate it, retry once on failure, 
   and surface errors explicitly instead of silently falling back.
8. Treat scanned code as untrusted input to the model. Comments in it may try 
   to steer the model.
9. All Cypher queries must be tested against a real FalkorDB instance 
   (Docker locally and in CI), not only with mocked results.
10. Terminal output uses Rich (panels, color-coded tables, trees). CLI uses 
    Typer. Color meaning: red/pink = critical, amber = warning, teal = clean, 
    lavender = structural info.

## Decisions made so far (keep unless I change them)
- Import-time code (module-level statements, decorators, default arguments)
  belongs to a pseudo-function `path.py::<module>`, created only for files
  that make calls at module level. Its source is the whole file.
- Unresolved callees are Function nodes with id `external::<full.dotted.name>`
  (aliases expanded, e.g. `sp.run` -> `subprocess.run`), `resolved: false`,
  and an `origin` (builtin | import | project | unknown). One node per name,
  shared across files; the call site lives on the CALLS edge (`lines`).
- Instantiating a project class with no `__init__` of its own writes no edge
  (no project code runs); it is counted, not dropped silently.
- Duplicate qualified names in one file get `#2`, `#3`, ...; calls resolve to
  the last definition.
- Function source is whole lines start_line..end_line, decorators included,
  CRLF normalised to LF. File sha256 is over the raw bytes.
- Module names: a file is importable by its path from the project root, by
  its path from the parent of the topmost package above it (directories
  without __init__.py below that are namespace packages), and by its bare
  name from a non-package directory. Ambiguous names resolve to the nearest
  file, or stay unresolved on a tie. Never guess.
- Endpoint id: `METHOD path -> handler_id`. FastAPI `app.mount()` of another
  FastAPI app is followed. `prefix_resolved: false` when a router is never
  mounted or a prefix is not a string literal. `auth_required` needs obvious
  evidence (auth-named Depends, also through an `Annotated` alias; any
  Security; auth-named decorator), stored in `auth_evidence`.
- A scan rebuilds the project's own graph (`gittrace_<folder>_<hash8>`):
  MERGE everything stamped with a scan_id, then delete what an older scan
  wrote. tree-sitter accepts most Python 2 syntax, so Python 2 files parse.
- A file's `<module>` node is also created when a finding sits at module
  level (e.g. a secret in a constants-only file), so the Sink has a function
  to hang from.
- One Sink per dangerous call site or secret assignment, id
  `path.py::line::col` (1-based column), linked
  (Function)-[:REACHES_SINK]->(Sink). Findings come from Sinks only.
- Hardcoded secret values are masked in every report and Sink snippet
  (first 3 characters kept, the rest `*`).
- `--depth` (default 10, max 50) is the maximum number of CALLS hops from a
  route handler to the vulnerable function; the blast radius counts callers
  within the same depth.
- A SQL query passed in unchanged as a parameter is not a finding; values
  are not followed across function calls (SQL built in one function and
  executed in another is a known false negative).
- `scan --offline` computes reachability in memory and writes no graph;
  `--no-blame` skips git blame. Severity is the fixed points table in
  gittrace/core/severity.py and the README; change both together.

## Phases (stop and report after each; do not start the next without approval)
- Phase 1: Fix existing bugs in the current code.
- Phase 2: Restructure into a package (gittrace/core, gittrace/graph, 
  gittrace/languages/python, gittrace/rules, gittrace/llm, gittrace/cli). 
  Remove the FastAPI web routes and the frontend/ directory. Keep the MCP 
  server working, importing from the new core.
- Phase 3: Python ingestion with tree-sitter into FalkorDB per the schema, 
  storing source spans. Include route detection for FastAPI and Flask 
  decorators.
- Phase 4: `gittrace scan`: rules for SQL built from strings, eval/exec, 
  shell commands with dynamic input, unsafe deserialization (pickle, 
  yaml.load), and hardcoded secrets; route-to-sink reachability (bounded 
  depth, unauthenticated routes first); blast radius over callers; Rich output.
- Phase 5: `gittrace explain`: per-file and per-function summaries and a 
  working-flow tree.
- Phase 6: LLM layer (Ollama default via LiteLLM) for explanations, severity 
  reasoning, and fix diffs validated with `git apply --check`.
- Phase 7: A sample vulnerable project in tests/fixtures with planted bugs and 
  expected findings, end-to-end tests, pipx packaging (pyproject.toml with a 
  `gittrace` entry point), and a README that states scope honestly 
  (Python only, which rules exist, what the model does vs. the rules).

## Out of scope unless I say otherwise
Web frontend, auto-applying fixes, git rollback loops, automatic PR creation, 
fine-tuning, languages other than Python.
