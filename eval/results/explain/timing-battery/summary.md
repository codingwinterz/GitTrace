# Explain results (timing-battery)

Prompt `explain-v2` (gittrace/llm sha256 `7f62a40da270`, explain code sha256 `a8aadf04f8c1`); GPU: NVIDIA GeForce RTX 5050 Laptop GPU, 8151 MiB; power at start: battery; no cache.

| Model | Target | Calls | Errors | Mentions kept / removed (summaries with removals) | s / function (mean, max) | s / file (mean) | s project | Total model s | Power before / after |
|---|---|---|---|---|---|---|---|---|---|
| ollama/llama3.1:8b | sample_app | 32 | 0 | 76 / 2 (2) | 2.44, 3.99 | 2.76 | 9.9 | 89.8 | battery / battery |
| ollama/llama3.1:8b | microblog | 70 | 0 | 163 / 4 (4) | 10.42, 262.14 | 3.57 | 11.9 | 498.0 | battery / battery |
| ollama/qwen2.5-coder:7b | sample_app | 32 | 0 | 85 / 2 (2) | 6.63, 9.21 | 6.52 | 17.0 | 221.2 | battery / battery |
| ollama/qwen2.5-coder:7b | microblog | 70 | 0 | 194 / 1 (1) | 10.12, 82.01 | 15.59 | 15.4 | 899.6 | battery / battery |
