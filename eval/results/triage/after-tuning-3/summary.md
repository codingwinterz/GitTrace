# Triage results (after-tuning-3)

Prompt `triage-v4` (gittrace/llm sha256 `a895edef1232`); set `measured` (vulpy-bad, vulpy-good, vulnerable-flask-app, vulnpy, dvga, ctfd, mealie); GPU: NVIDIA GeForce RTX 5050 Laptop GPU, 8151 MiB; no cache.

| Model | Findings (TP / FP) | FP marked likely_harmless | **TP marked likely_harmless** | Uncertain | Errors | Retries | Fixes that apply | s / finding (mean, median, max) |
|---|---|---|---|---|---|---|---|---|
| ollama/qwen2.5-coder:7b | 52 (35 / 17) | 11/17 (65%) | **9/35 (26%)** | 1/52 (2%) | 0 | 0 | 28/31 offered | 2.35, 2.12, 4.31 |
| ollama/llama3.1:8b | 52 (35 / 17) | 14/17 (82%) | **1/35 (3%)** | 2/52 (4%) | 0 | 5 | 27/30 offered | 2.55, 2.24, 4.84 |

Verdicts by label:

| Model | Label | likely_real | uncertain | likely_harmless | error | mean adjustment |
|---|---|---|---|---|---|---|
| ollama/qwen2.5-coder:7b | TP | 25 | 1 | 9 | 0 | -0.11 |
| ollama/qwen2.5-coder:7b | FP | 6 | 0 | 11 | 0 | 0 |
| ollama/llama3.1:8b | TP | 33 | 1 | 1 | 0 | -0.06 |
| ollama/llama3.1:8b | FP | 2 | 1 | 14 | 0 | 0 |

Per target (FP marked harmless / TP marked harmless / uncertain):

| Target | ollama/qwen2.5-coder:7b | ollama/llama3.1:8b |
|---|---|---|
| vulpy-bad | FP 0/1 · TP 1/5 · unc 0/6 | FP 1/1 · TP 0/5 · unc 0/6 |
| vulpy-good | FP 0/0 · TP 3/5 · unc 0/5 | FP 0/0 · TP 0/5 · unc 0/5 |
| vulnerable-flask-app | FP 0/0 · TP 1/4 · unc 1/4 | FP 0/0 · TP 0/4 · unc 1/4 |
| vulnpy | FP 0/0 · TP 0/15 · unc 0/15 | FP 0/0 · TP 0/15 · unc 0/15 |
| dvga | FP 0/0 · TP 2/4 · unc 0/4 | FP 0/0 · TP 0/4 · unc 0/4 |
| ctfd | FP 2/3 · TP 0/0 · unc 0/3 | FP 2/3 · TP 0/0 · unc 0/3 |
| mealie | FP 9/13 · TP 2/2 · unc 0/15 | FP 11/13 · TP 1/2 · unc 1/15 |

True positives marked likely_harmless:

- ollama/qwen2.5-coder:7b: `vulpy.py::16::1` (GT-SECRET-001, vulpy-bad): The SECRET_KEY is hardcoded and does not appear to be used in a way that could be exploited by an attacker.
- ollama/qwen2.5-coder:7b: `libapi.py::10::1` (GT-SECRET-001, vulpy-good): The secret is hardcoded but only used in internal functions and not exposed to users.
- ollama/qwen2.5-coder:7b: `libsession.py::9::1` (GT-SECRET-001, vulpy-good): The secret is hardcoded but only used in test configuration, not in production code.
- ollama/qwen2.5-coder:7b: `vulpy.py::17::1` (GT-SECRET-001, vulpy-good): The SECRET_KEY is hardcoded and does not appear to be used in a way that could be exploited by an attacker.
- ollama/qwen2.5-coder:7b: `app/app.py::63::9` (GT-SECRET-001, vulnerable-flask-app): The hardcoded password is used in a setup script and does not appear to be exposed to users.
- ollama/qwen2.5-coder:7b: `app.py::14::1` (GT-SECRET-001, dvga): The SECRET_KEY is hardcoded but not used in a way that could be exploited by an attacker. It is set to a random value and not a placeholder.
- ollama/qwen2.5-coder:7b: `app.py::15::1` (GT-SECRET-001, dvga): The JWT_SECRET_KEY is hardcoded but not used in a way that could be exploited by an attacker.
- ollama/qwen2.5-coder:7b: `mealie/core/settings/db_providers.py::38::5` (GT-SECRET-001, mealie): The POSTGRES_PASSWORD is hardcoded and does not appear to be used in a way that could be influenced by user input. It is used in a Pydantic settings class and does not seem to be dynamically set based on user input.
- ollama/qwen2.5-coder:7b: `mealie/core/settings/settings.py::290::5` (GT-SECRET-001, mealie): The value is a hardcoded secret, but it is not used in a way that could be exploited by an attacker. It is only used as a default password and is not exposed in any way that could be accessed by a user.
- ollama/llama3.1:8b: `mealie/core/settings/db_providers.py::38::5` (GT-SECRET-001, mealie): The secret is hardcoded in the code, but it's only used for a PostgreSQL database connection, which is not user-facing.
