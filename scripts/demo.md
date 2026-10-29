# Two-minute demo

A script for recording GitTrace in about two minutes, on the bundled sample app
(`tests/fixtures/sample_app`, a small FastAPI app with planted bugs). Every number said aloud
below is asserted by the test suite or measured in `eval/`, so the recording cannot drift from
what the tool does.

## Before recording (not on camera)

```bash
cd GitTrace                                   # a clone; run everything from its root
gittrace up --pull                            # both Ollama models
gittrace doctor                               # every row OK
gittrace scan tests/fixtures/sample_app > /dev/null          # warms the model cache (~1.5 min)
gittrace explain tests/fixtures/sample_app --yes > /dev/null # warms the explain cache (~1 min)
```

- The model replies are now cached (`tests/fixtures/sample_app/.gittrace/cache`), so the
  recorded runs are instant and give the same verdicts. Say so on camera; it is not a trick.
- Terminal at least 110 × 32, a large font, a dark theme. Clear the scrollback.
- Keep the machine awake and plugged in (`gittrace doctor` shows sleep settings; on Windows
  `powercfg /change standby-timeout-ac 0` and `powercfg /change monitor-timeout-ac 0`).
- Nothing secret on screen: no `.env`, no shell history with tokens. GitTrace masks the sample's
  planted secrets itself.

## The recording

| Time | Do | Say |
|---|---|---|
| 0:00–0:12 | `gittrace --version` | "GitTrace scans a Python web project and shows which dangerous code an HTTP route can actually reach. Everything here runs locally: the graph in the GitTrace process, a model in Ollama." |
| 0:12–0:45 | `gittrace scan tests/fixtures/sample_app`, then scroll to finding 1 | "Rules found 13 findings. The first is SQL built with an f-string in `app/db.py`, line 17. It is critical: an unauthenticated route reaches it. Here is the path, `GET /api/users/{name}` to `read_user` to `Repo.get_user`, its blast radius of 5, and who last changed the line." |
| 0:45–1:00 | Point at the model line under finding 1, then at the "Likely harmless" section | "A local model, llama3.1:8b, gives an opinion on each finding: a verdict, where each value comes from, and an adjustment shown next to the rules' score, never instead of it. It cannot add or remove findings." |
| 1:00–1:15 | `gittrace blast-radius app/db.py::Repo.get_user -p tests/fixtures/sample_app` | "The graph answers the follow-up questions: everything that calls this function, and every endpoint that reaches it." |
| 1:15–1:40 | `gittrace` (interactive), wait for the logo to turn, then type `/explain tests/fixtures/sample_app` | "For people who built an app with AI and don't fully understand it, `explain` describes it in plain language: entry points, endpoints, what each function does and what it touches." |
| 1:40–1:52 | `ctrl+q`, then `gittrace scan tests/fixtures/sample_app --offline --no-llm --format json --fail-on high > /dev/null; echo $?` | "In CI it is a gate: exit code 1 when a finding is high or above. The gate reads only the deterministic rules." |
| 1:52–2:00 | Show the README's "Results at a glance" | "On the five categories it covers, it is comparable to Bandit, with added reachability and ownership context. The evaluation and its limits are in the README." |

## If something goes wrong on camera

- A model call is slow or errors: the scan continues and shows the error on that finding. Cut, re-run (cached replies are instant).
- `doctor` shows a FAIL: fix it before recording; it prints the command to run.
- The interactive logo does not move: the terminal is smaller than 80 × 24, or `NO_COLOR` is set.
