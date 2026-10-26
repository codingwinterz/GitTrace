# Explain results (untouched)

Prompt `explain-v1` (gittrace/llm sha256 `86f7d61d97e0`); GPU: NVIDIA GeForce RTX 5050 Laptop GPU, 8151 MiB; power at start: battery; no cache.

| Model | Target | Calls | Errors | Mentions kept / removed (summaries with removals) | s / function (mean, max) | s / file (mean) | s project | Total model s |
|---|---|---|---|---|---|---|---|---|
| ollama/llama3.1:8b | sample_app | 32 | 0 | 79 / 7 (6) | 6.43, 8.32 | 7.41 | 25.0 | 237.1 |
| ollama/llama3.1:8b | microblog | 70 | 0 | 191 / 2 (2) | 7.96, 10.6 | 9.89 | 16.0 | 630.6 |
| ollama/qwen2.5-coder:7b | sample_app | 32 | 0 | 76 / 1 (1) | 1.84, 3.66 | 1.82 | 5.5 | 62.2 |
| ollama/qwen2.5-coder:7b | microblog | 70 | 0 | 218 / 5 (3) | 1.99, 4.06 | 3.31 | 12.6 | 194.7 |
