# Explain results (after-tuning)

Prompt `explain-v2` (gittrace/llm sha256 `7f62a40da270`, explain code sha256 `a8aadf04f8c1`); GPU: NVIDIA GeForce RTX 5050 Laptop GPU, 8151 MiB; power at start: battery; no cache.

| Model | Target | Calls | Errors | Mentions kept / removed (summaries with removals) | s / function (mean, max) | s / file (mean) | s project | Total model s | Power before / after |
|---|---|---|---|---|---|---|---|---|---|
| ollama/llama3.1:8b | sample_app | 32 | 0 | 76 / 2 (2) | 2.32, 3.8 | 2.61 | 9.4 | 85.0 | battery / battery |
| ollama/llama3.1:8b | microblog | 70 | 0 | 163 / 4 (4) | 4.87, 73.57 | 3.32 | 11.5 | 294.8 | battery / battery |
| ollama/qwen2.5-coder:7b | sample_app | 32 | 0 | 85 / 2 (2) | 2.53, 4.52 | 2.5 | 7.3 | 85.3 | battery / battery |
| ollama/qwen2.5-coder:7b | microblog | 70 | 0 | 194 / 1 (1) | 2.77, 5.06 | 3.4 | 8.1 | 220.4 | battery / battery |
