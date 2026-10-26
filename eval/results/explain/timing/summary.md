# Explain results (timing)

Prompt `explain-v2` (gittrace/llm sha256 `edbf0c30a4cb`, explain code sha256 `17b003bf97de`); GPU: NVIDIA GeForce RTX 5050 Laptop GPU, 8151 MiB; power at start: AC; no cache.

| Model | Target | Calls | Errors | Mentions kept / removed (summaries with removals) | s / function (mean, max) | s / file (mean) | s project | Total model s | Power before / after |
|---|---|---|---|---|---|---|---|---|---|
| ollama/llama3.1:8b | sample_app | 32 | 0 | 75 / 4 (4) | 1.73, 3.33 | 2.18 | 8.4 | 67.9 | AC / AC |
| ollama/llama3.1:8b | microblog | 70 | 0 | 174 / 3 (3) | 45.55, 1523.93 | 2.68 | 6.0 | 1691.1 | AC / AC |
| ollama/qwen2.5-coder:7b | sample_app | 32 | 0 | 85 / 2 (2) | 20.49, 331.31 | 1.86 | 5.5 | 398.4 | AC / AC |
| ollama/qwen2.5-coder:7b | microblog | 70 | 0 | 194 / 1 (1) | 2.1, 4.32 | 2.61 | 6.8 | 169.0 | AC / AC |
