# GitTrace v2 — Project Plan

## Goal
GitTrace is a CLI tool that scans any Python project folder, builds a code 
graph (in-process, NetworkX) from the real code, finds vulnerabilities that are actually 
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
9. All graph queries must be tested against the real graph store
   (gittrace.graph.memstore.GraphStore) and its cache, not only with mocked
   results. No database server, no Docker.
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
- A scan rebuilds the project's own graph (`gittrace_<folder>_<hash8>`)
  from scratch in a GraphStore (NetworkX DiGraph; nodes keyed by
  (label, id); merge semantics: an edge only when both nodes exist, at most
  one edge per node pair) and caches it in `<project>/.gittrace/graph.json`,
  written atomically (temp file + os.replace) with the sha256 of every
  discovered source file. A cache whose hashes do not match is never
  served: the tools report "out of date; run scan again". Function `source`
  is kept in memory but not cached (it can hold secrets). Graph
  reachability breaks shortest-path ties by the smallest ids, like the
  in-memory backend. tree-sitter accepts most Python 2 syntax, so Python 2
  files parse.
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

- Findings in test code (a `tests`/`test` directory, test_*.py, *_test.py,
  conftest.py) are reported in a separate section at info severity and never
  trip `--fail-on`; `--include-tests` treats them like any other code.
- Evaluation (eval/): ground truth is written before a tool is run on a
  target; the untouched, after-tuning and held-out results are kept as
  separately labelled runs. A held-out target is run once and nothing is
  changed because of its results.
- Model layer (gittrace/llm): `ollama/<name>` is called through LiteLLM's
  `ollama_chat/` provider (the plain `ollama/` one flattens system and user
  messages into one prompt). num_ctx 8192, temperature 0.1, seed 7, at most
  1024 reply tokens, timeout 120 s ($GITTRACE_LLM_TIMEOUT). The pydantic
  schema is also sent as the JSON schema, so Ollama constrains decoding.
- Model errors: cannot call the model at all (connection, model not
  pulled, auth) stops the scan with exit 2; a timeout, a failed call or two
  invalid replies is an error on that finding, shown next to it, the other
  findings are still triaged, and errors are never cached.
- Triage runs on the findings shown (`--min-severity`), not on test-code
  findings unless `--include-tests`. `--fail-on` reads the rules' severity
  only; the model's adjustment is shown beside the rules' score, never
  instead of it. likely_harmless findings get their own report section.
- Fixes: the model returns replacement text for a fix region (the flagged
  statement, extended up to the earliest assignment of its `via` variable
  within 10 lines above); GitTrace re-bases its indentation, builds the
  unified diff, and checks that the file still parses (when it parsed
  before) and that `git apply --check` accepts it in a temporary directory.
  "Valid" means applies cleanly, not correct.
- Everything copied from the scanned project goes inside the
  BEGIN_UNTRUSTED_<id> / END_UNTRUSTED_<id> fence (<id> derived from the
  content); hardcoded secrets are masked in prompts; model text is stripped
  of control characters. Prompt budget: 3 characters per token, 8192 minus
  the reply, the system prompt and 256; the enclosing function is cut first.
- Cache: `<project>/.gittrace/cache`, key sha256 over task, model,
  PROMPT_VERSION and the prompt's sha256; entries are validated on read;
  `.gittrace/` holds a `*` .gitignore and discovery skips it. Bump
  PROMPT_VERSION whenever the system prompt or the prompt layout changes.
- Triage reply: `values` (each value flowing into the call, with source
  constant | internal | attacker | unknown) comes before `verdict`;
  likely_harmless is rejected while any value is attacker or unknown. A
  hardcoded secret is listed as a value: attacker when the application
  uses it, constant only when only tests use it. Secret prompts state the
  real value's length, character classes and distinct characters.
- Triage evaluation: measured set = the four vulnerable targets, DVGA, CTFd,
  mealie; held-out set = open-webui, used once and only after any tuning.
  Prompt versions and their runs: triage-v1 untouched, triage-v2
  after-tuning-1, triage-v3 after-tuning-2 and held-out, triage-v4
  after-tuning-3 (current; severity_adjustment counts only what the
  rules' score does not, and the prompt lists the factors already scored).
  held-out was not re-run for v4.
- Default model: ollama/llama3.1:8b (hid 1 of 35 true positives on the
  tuning set against qwen2.5-coder:7b's 10, all secrets; 0 flips in the
  injection probe against 2). It takes 5.6 GiB of VRAM at num_ctx 8192
  (measured peak 6.7 of 8 GB with the desktop's own use).
- Out of GPU memory (Ollama only): wait 5 s and retry once at the same
  num_ctx; if it fails again and the prompt plus reply fit in 4096, retry
  once with num_ctx 4096. Each recovery is a note on the finding and
  counted in the summary; a reduced-context reply is not cached. Model
  errors carry their real attempts and seconds.
- Eval output never holds a raw secret value: eval/hygiene.py scrubs
  everything run_eval.py and run_triage.py write and fails the run on a
  leak; tests/test_eval_hygiene.py checks the committed results against
  eval/secret_values.sha256 (hashes only). Hash-locked ground-truth files
  are inputs and keep their text. Don't rewrite git history for values
  that are public defaults (mealie's MyPassword).
- Fixes are opt-in (`scan --fix`). Without it the prompt is still exactly
  the measured one (now triage-v4) and only the reply schema changes
  (TriageVerdict: fix_code may only be null); with triage-v3 the verdicts
  matched the measured run 52/52 for both models (not re-measured for
  v4). Cache task names: "triage" (with --fix), "triage-verdict".
  A prompt with the fix paragraph removed hid more true positives; it is
  archived in eval/results/triage/no-fix-paragraph/ and not used.
- `explain` (Phase 6): facts in memory from the same analysis as
  `scan --offline` (no graph); the rule findings are run offline by
  explain itself for the security notes. Language plug-ins provide
  `project_facts` (ImportFact, EntryPointDef, EffectFact, ServiceFact) and
  docstrings (FunctionDef.doc, FileRecord.doc); none of it is written to
  the graph. Important functions: route handlers, entry points, and
  functions called from >= --min-callers (3) other functions; a file's
  <module> is part of the file summary, never a function summary.
- `explain` summaries: bottom-up (functions leaves first, then files, then
  the project), EXPLAIN_VERSION explain-v1, cache tasks explain-function /
  explain-file / explain-project. Grounding: a mention is kept only if it is
  the described function, a direct caller or a direct callee (file: its
  functions and their callers and callees; project: any project function);
  a bare name only when exactly one allowed function has it; unverified ids
  in the text are replaced by "[unverified reference removed]". --file
  summarises the file and all its functions; --function one function. The
  run is estimated at SECONDS_PER_CALL per model call and needs --yes (or an
  interactive yes) above 10 minutes.
- Explain evaluation: references (eval/explain/<target>/reference.json) and
  the 30-function sample (eval/explain/sample.json, seed 7, 10 sample_app +
  20 microblog) were written and hashed (eval/explain/reference.sha256)
  before any summary existed. Ratings: correct (every statement true, main
  purpose covered) / partly (main purpose right, a false or misleading
  detail or a missing key point) / wrong (main purpose wrong or a central
  claim false). The first run is `untouched`; any tuning gets a new
  EXPLAIN_VERSION and a separately labelled run. Ratings are made by an AI
  against the pre-written references, plus the owner's spot checks.
- explain-v2 (the `after-tuning` run): the prompt's example id is the fake
  `example/module.py::Example.method` (v1's was a real sample_app id and a
  model copied it); side effects include reads, as in the facts. Effect
  kinds add store_read / store_write (search indexes, caches, queues; Redis
  moved there from db_*). Flask-SQLAlchemy helpers (db.paginate,
  get_or_404, first_or_404, one_or_404 read; create_all / drop_all write),
  session rollback (db), Elasticsearch / OpenSearch, RQ / Celery, Flask-Mail,
  HTTP client objects, aiofiles / Path.open / zipfile / tarfile,
  send_file and uploaded-file save() are classified. A method on an object
  built by a library constructor is classified by that type first
  (facts.receiver_types: module or local assignment, import, `with ... as`);
  building a client is not an effect; Flask's `session` is not a database.
- Glossary (gittrace/core/glossary.py): a fixed list of terms with plain
  definitions; every summary gets the terms its prose uses ("Terms used"),
  computed from the reply after the grounding check, never cached, never
  from the model. Code-like text (paths, ids, dotted names, backticks) is
  ignored; acronyms must be upper case.
- `explain` model: --model, else $GITTRACE_EXPLAIN_MODEL, else
  ollama/qwen2.5-coder:7b (more summaries right in 5 of 6 comparisons,
  less VRAM; equally fast when run back to back). $GITTRACE_MODEL and
  llama3.1:8b stay triage's.
- Explain held-out target: testdrivenio/fastapi-tdd-docker at 16433b6
  (eval/explain/targets_held_out.json), all 7 important functions sampled;
  references hashed in eval/explain/reference_held_out.sha256 before any
  model ran on it; run once (`--set held-out --label held-out`), nothing
  changed because of it. Timings come from a separate `timing` run with
  `--require-ac`, reported apart from quality. Run on AC (`timing`): the
  models are equally fast (~2.1 s per call; per function 1.86 s llama,
  2.04 s qwen, medians), two calls interrupted by Modern Standby are left
  out (eval/results/explain/timing/NOTES.md); a battery pass
  (`timing-battery`) was too confounded by the falling charge to compare
  the models.

- Interactive mode (Textual, gittrace/cli/interactive.py): opens only for
  `gittrace` with no arguments (or `--no-anim`) when stdin and stdout are
  terminals; anything else is the Typer CLI unchanged. Slash commands are
  parsed and run by gittrace/cli/session.py (no Textual) with the CLI's
  defaults and render functions, on a daemon thread, output captured as
  ANSI into a RichLog; errors are CommandError, never an exit; /explain
  over 10 minutes needs --yes. Logo math in gittrace/cli/logo.py: 12x28
  cells, 40 precomputed frames (2 s at 20 fps, eased), 5 s hold with the
  timer paused, still while a command runs, static with --no-anim,
  NO_COLOR or a terminal under 80x24. Version: gittrace.__version__.

- No database: FalkorDB, Docker, Redis, `graphs`, `--allow-remote` and the
  FALKORDB_* settings were removed (branch remove-docker). core.scan /
  pipeline.ingest take an empty GraphStore as `graph=` (the caller's own,
  not saved); without one they build one and save the cache.
- Display: the git blame owner is shown by name only; --show-email adds the
  email (rich and JSON); the graph stores the full author, and the graph
  tools (MCP) show the email only with GITTRACE_SHOW_EMAIL=1.
  GT-SECRET-* findings hide the model's "inputs" line (display only). A
  parse failure is reported once, in the summary (the log line is debug).
- Phase 7 (packaging): pyproject.toml (setuptools, version from
  gittrace.__version__), commands `gittrace` and `gittrace-mcp`;
  requirements.txt is `-e .[dev]`. Settings (gittrace.config): environment,
  then the first of $GITTRACE_ENV_FILE, a checkout's .env, the user config
  dir's .env; never the current directory's. `doctor` (gittrace/cli/
  machine.py, all probes through System for tests) exits 1 on a failed
  check; `up` checks Ollama and --pull pulls missing models. Graph tools
  (MCP, trace, blast-radius) hide the owner email unless
  GITTRACE_SHOW_EMAIL=1. git on scanned repos runs with
  core.fsmonitor=false and blame --no-textconv. Typer tracebacks never
  show locals. explain estimate 2.1 s/call (AC timing); explain code
  sha256 8665e416d4ef for the recorded explain results; after the gateway
  change the covered files hash to fbc156c36353 (explain eval not re-run). CI `package` job builds, pipx-installs and
  smoke-tests on Linux and Windows.

## Backlog (not scheduled; do not start without approval)
- `getattr` / `import_module` dispatch and routes registered dynamically in
  loops (`add_url_rule` with computed names, decorators applied inside
  factory functions, GraphQL resolvers dispatched by graphene). Mostly out of
  reach for static analysis: document it as a limitation rather than guess
  edges.
- Cross-function SQL propagation: a query built in one function (or returned
  by a helper) and executed in another, e.g. `execute(build_query())` and
  `run_cmd(f"curl {url}")` reaching a sink through a wrapper with a constant
  at some call sites and attacker input at others.
- Found in the held-out run, not fixed: auth dependency names outside the
  pattern (`get_verified_user`), secrets passed as keyword arguments
  (`User(password="...")`) or in dict literals, and secret names ending in
  `HMAC` (`SECRET_KEY_HMAC`).
- Found in the explain held-out run (fastapi-tdd-docker), not fixed: no
  side effects for the Tortoise ORM (`Model.filter(...).first()`, `.save()`,
  `.update()`, `.delete()`, `Model.all()`) or for downloads done by
  libraries (newspaper's `Article.download`, `nltk.download`), so summaries
  say "side effects: none" for handlers that use the database.
- Grounding check vs. the facts: a function's prompt names the functions
  further down that cause its side effects (effects_via, up to five hops),
  but a mention is only kept for direct callers and callees, so a correct
  mention of such a function is removed (microblog's `search` ->
  `query_index`).

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
- Phase 5: LLM layer (Ollama default via LiteLLM) plus scan triage: model
  chosen by --model, then $GITTRACE_MODEL, then ollama/llama3.1:8b;
  --no-llm skips every model call; a pydantic schema per task, validated,
  one retry, then a clear error; scanned code fenced as untrusted data; a
  token-budgeted context per finding; per finding a verdict (likely_real |
  likely_harmless | uncertain), a reason and a severity adjustment of -2..+1
  shown next to the deterministic score; findings are never removed; an
  optional fix diff checked with `git apply --check` on a temporary copy;
  responses cached in .gittrace/cache; triage measured on the labelled
  eval data for qwen2.5-coder:7b and llama3.1:8b.
- Phase 6: `gittrace explain`: per-file and per-function summaries and a 
  working-flow tree.
- Phase 7: A sample vulnerable project in tests/fixtures with planted bugs and 
  expected findings, end-to-end tests, pipx packaging (pyproject.toml with a 
  `gittrace` entry point), and a README that states scope honestly 
  (Python only, which rules exist, what the model does vs. the rules).

## Out of scope unless I say otherwise
Web frontend, auto-applying fixes, git rollback loops, automatic PR creation, 
fine-tuning, languages other than Python.
