# Triage results (held-out)

Prompt `triage-v3` (gittrace/llm sha256 `25ef9a865a92`); set `held-out` (open-webui); GPU: NVIDIA GeForce RTX 5050 Laptop GPU, 8151 MiB; no cache.

| Model | Findings (TP / FP) | FP marked likely_harmless | **TP marked likely_harmless** | Uncertain | Errors | Retries | Fixes that apply | s / finding (mean, median, max) |
|---|---|---|---|---|---|---|---|---|
| ollama/qwen2.5-coder:7b | 29 (2 / 27) | 12/27 (44%) | **0/2 (0%)** | 0/29 (0%) | 0 | 0 | 10/14 offered | 2.8, 2.52, 4.94 |
| ollama/llama3.1:8b | 29 (2 / 27) | 11/27 (41%) | **0/2 (0%)** | 3/29 (10%) | 1 | 1 | 1/1 offered | 3.99, 3.33, 13.88 |

Verdicts by label:

| Model | Label | likely_real | uncertain | likely_harmless | error | mean adjustment |
|---|---|---|---|---|---|---|
| ollama/qwen2.5-coder:7b | TP | 2 | 0 | 0 | 0 | 0 |
| ollama/qwen2.5-coder:7b | FP | 15 | 0 | 12 | 0 | -0.07 |
| ollama/llama3.1:8b | TP | 2 | 0 | 0 | 0 | 0 |
| ollama/llama3.1:8b | FP | 12 | 3 | 11 | 1 | 0.11 |

Per target (FP marked harmless / TP marked harmless / uncertain):

| Target | ollama/qwen2.5-coder:7b | ollama/llama3.1:8b |
|---|---|---|
| open-webui | FP 12/27 · TP 0/2 · unc 0/29 | FP 11/27 · TP 0/2 · unc 3/29 |
