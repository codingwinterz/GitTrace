## GitTrace 2.1.0: no Docker, no database server

GitTrace now builds its code graph in memory and caches it in `<project>/.gittrace/graph.json`. You no longer need Docker or FalkorDB. The only optional program left is Ollama, for the local model, and `--no-llm` scans don't need it.

### Install

Python 3.12-3.14:

    pipx install "git+https://github.com/codingwinterz/GitTrace@v2.1.0"
    gittrace --version

With uv: `uv tool install --python 3.14 "git+https://github.com/codingwinterz/GitTrace@v2.1.0"`

### What's new

- **In-process graph (NetworkX)** replaces FalkorDB. The four graph tools (`list_findings`, `trace_attack_path`, `blast_radius`, `finding_owner`) keep their names and output formats. On the evaluation targets, route paths and blast radius came out identical to the FalkorDB version for all 76 findings checked.
- **Cache safety:** the cache records a hash of every source file and is refused once any file changes. It's written atomically, and it doesn't store function source code, so secrets in the project aren't copied into it.
- **More routes found:** Falcon (`app.add_route`), Flask `add_url_rule` (including in loops), and `threading.Thread(target=...)` calls are now followed.
- **getattr dispatch:** `getattr(obj, name)()` on a project object held in a variable is followed as a low-confidence, `dynamic` edge.
- **Optional Respan Gateway:** `pip install "gittrace[gateway] ..."` plus `GITTRACE_GATEWAY=1` routes model calls through it. A plain install doesn't include it.
- **Claims are checked:** every reachability number in the docs is tied to a run label and verified against the evaluation results by a test.
- **Python 3.12-3.14:** `requires-python = ">=3.12,<3.15"`, so Python 3.15 gets a clear installer message and not a failed build.

### Breaking changes

- Removed: `gittrace graphs`, the `--allow-remote` flag (on `scan` and `/scan`), and the `FALKORDB_*` settings.
- `gittrace up` no longer starts a container; it checks Ollama and pulls models with `--pull`.
- `gittrace doctor` no longer checks Docker or a database.
- Python 3.11 is no longer supported.
- Graphs previously stored in FalkorDB are not migrated. Run `gittrace scan` again.

### Results

Reachability on the four vulnerable test apps (20 ground-truth entries), by run:

- Marked reachable: `untouched`: 7 marked, 0 wrong; `after-reachability`: 7 marked, 0 wrong; `after-reach-fixes`: 7 marked, 0 wrong.
- Marked reachable without auth: `untouched`: 7 marked, 1 wrong; `after-reachability`: 6 marked, 0 wrong (the auth-detection fix); `after-reach-fixes`: 6 marked, 0 wrong.

The 13 entries it still misses are all in vulnpy: 11 are reached through `getattr`/`import_module` dispatch, and 2 through Falcon routes that vulnpy binds conditionally. Full per-run numbers are in `eval/README.md`.

### Known limits

Python only; FastAPI, Flask, Flask-RESTful/RESTX and Falcon routes; five finding categories; dynamic dispatch is not resolved. Small evaluation samples: read the numbers as indications, not benchmarks.

**Full changelog:** see `CHANGELOG.md`.
