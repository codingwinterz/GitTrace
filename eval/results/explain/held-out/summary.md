# Explain results (held-out)

Prompt `explain-v2` (gittrace/llm sha256 `7f62a40da270`, explain code sha256 `a8aadf04f8c1`); GPU: NVIDIA GeForce RTX 5050 Laptop GPU, 8151 MiB; power at start: battery; no cache.

| Model | Target | Calls | Errors | Mentions kept / removed (summaries with removals) | s / function (mean, max) | s / file (mean) | s project | Total model s | Power before / after |
|---|---|---|---|---|---|---|---|---|---|
| ollama/llama3.1:8b | fastapi-tdd-docker | 26 | 0 | 57 / 3 (3) | 2.86, 4.14 | 2.74 | 9.5 | 78.9 | battery / battery |
| ollama/qwen2.5-coder:7b | fastapi-tdd-docker | 26 | 0 | 70 / 7 (4) | 2.74, 4.68 | 3.07 | 7.8 | 82.3 | battery / battery |
