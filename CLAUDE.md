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
