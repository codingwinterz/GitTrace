# Notes on the timing run

Written by hand after the run; the other files here are the script's output, unchanged.

Run: 2026-10-26, 17:12:33 to 17:51:54 local time, `python eval/run_explain.py --label timing --require-ac`.
Power: AC at the start and before and after each model (`BatteryStatus.PowerOnline`);
battery at 16% and charging at the start; Windows power plan "Turbo".

The laptop entered Modern Standby twice while plugged in (Windows System event log,
Microsoft-Windows-Kernel-Power events 506 "entering" / 507 "exiting"):

| Standby | Length | Call it fell inside | Recorded seconds |
|---|---|---|---|
| 17:13:33 to 17:39:13 | 1540 s | llama3.1:8b, microblog, function `app/__init__.py::create_app` (its first microblog call) | 1523.93 |
| 17:42:42 to 17:48:19 | 337 s | qwen2.5-coder:7b, sample_app, function `app/routers/reports.py::version` | 331.31 |

Both calls returned a valid summary on the first attempt; the 120 s reply timeout did
not fire because the whole machine, Ollama included, was suspended. `PowerOnline` stays
True in standby, so `--require-ac` does not detect it.

The README and eval/README.md report this run without those two calls. Every other call
took 1.06 to 8.43 s.

Used since (Phase 7): `explain`'s estimate before a run is 2.1 s per model call for both
models (MODEL_SECONDS_PER_CALL in gittrace/llm/explain.py), from these figures. With that
change the explain code sha256 is `8665e416d4ef` (it also covers triage prompt v4, which no
explain prompt uses); see eval/README.md, "Code hashes".
