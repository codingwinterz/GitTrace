# Triage results (untouched)

Prompt `triage-v1` (gittrace/llm sha256 `b54e5abc5879`); set `measured` (vulpy-bad, vulpy-good, vulnerable-flask-app, vulnpy, dvga, ctfd, mealie); GPU: NVIDIA GeForce RTX 5050 Laptop GPU, 8151 MiB; no cache.

| Model | Findings (TP / FP) | FP marked likely_harmless | **TP marked likely_harmless** | Uncertain | Errors | Retries | Fixes that apply | s / finding (mean, median, max) |
|---|---|---|---|---|---|---|---|---|
| ollama/qwen2.5-coder:7b | 52 (35 / 17) | 0/17 (0%) | **0/35 (0%)** | 0/52 (0%) | 0 | 0 | 47/51 offered | 1.96, 1.7, 4.08 |
| ollama/llama3.1:8b | 52 (35 / 17) | 1/17 (6%) | **0/35 (0%)** | 0/52 (0%) | 0 | 0 | 45/50 offered | 1.99, 1.76, 4.87 |

Verdicts by label:

| Model | Label | likely_real | uncertain | likely_harmless | error | mean adjustment |
|---|---|---|---|---|---|---|
| ollama/qwen2.5-coder:7b | TP | 35 | 0 | 0 | 0 | -0.03 |
| ollama/qwen2.5-coder:7b | FP | 17 | 0 | 0 | 0 | 0 |
| ollama/llama3.1:8b | TP | 35 | 0 | 0 | 0 | 0.11 |
| ollama/llama3.1:8b | FP | 16 | 0 | 1 | 0 | 0 |

Per target (FP marked harmless / TP marked harmless / uncertain):

| Target | ollama/qwen2.5-coder:7b | ollama/llama3.1:8b |
|---|---|---|
| vulpy-bad | FP 0/1 · TP 0/5 · unc 0/6 | FP 0/1 · TP 0/5 · unc 0/6 |
| vulpy-good | FP 0/0 · TP 0/5 · unc 0/5 | FP 0/0 · TP 0/5 · unc 0/5 |
| vulnerable-flask-app | FP 0/0 · TP 0/4 · unc 0/4 | FP 0/0 · TP 0/4 · unc 0/4 |
| vulnpy | FP 0/0 · TP 0/15 · unc 0/15 | FP 0/0 · TP 0/15 · unc 0/15 |
| dvga | FP 0/0 · TP 0/4 · unc 0/4 | FP 0/0 · TP 0/4 · unc 0/4 |
| ctfd | FP 0/3 · TP 0/0 · unc 0/3 | FP 1/3 · TP 0/0 · unc 0/3 |
| mealie | FP 0/13 · TP 0/2 · unc 0/15 | FP 0/13 · TP 0/2 · unc 0/15 |
