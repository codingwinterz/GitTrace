# Triage results (default-no-fix)

Prompt `triage-v3` (gittrace/llm sha256 `5367704ee313`); set `measured` (vulpy-bad, vulpy-good, vulnerable-flask-app, vulnpy, dvga, ctfd, mealie); GPU: NVIDIA GeForce RTX 5050 Laptop GPU, 8151 MiB; no cache.

| Model | Findings (TP / FP) | FP marked likely_harmless | **TP marked likely_harmless** | Uncertain | Errors | Retries | Fixes that apply | s / finding (mean, median, max) |
|---|---|---|---|---|---|---|---|---|
| ollama/qwen2.5-coder:7b | 52 (35 / 17) | 11/17 (65%) | **10/35 (29%)** | 1/52 (2%) | 0 | 0 | 0/0 offered | 3.21, 2.8, 7.4 |
| ollama/llama3.1:8b | 52 (35 / 17) | 14/17 (82%) | **1/35 (3%)** | 3/52 (6%) | 0 | 0 | 0/0 offered | 3.44, 2.81, 9.27 |

Verdicts by label:

| Model | Label | likely_real | uncertain | likely_harmless | error | mean adjustment |
|---|---|---|---|---|---|---|
| ollama/qwen2.5-coder:7b | TP | 24 | 1 | 10 | 0 | 0 |
| ollama/qwen2.5-coder:7b | FP | 6 | 0 | 11 | 0 | 0 |
| ollama/llama3.1:8b | TP | 32 | 2 | 1 | 0 | 0.37 |
| ollama/llama3.1:8b | FP | 2 | 1 | 14 | 0 | 0.06 |

Per target (FP marked harmless / TP marked harmless / uncertain):

| Target | ollama/qwen2.5-coder:7b | ollama/llama3.1:8b |
|---|---|---|
| vulpy-bad | FP 0/1 · TP 2/5 · unc 0/6 | FP 1/1 · TP 0/5 · unc 0/6 |
| vulpy-good | FP 0/0 · TP 4/5 · unc 0/5 | FP 0/0 · TP 0/5 · unc 0/5 |
| vulnerable-flask-app | FP 0/0 · TP 1/4 · unc 1/4 | FP 0/0 · TP 0/4 · unc 1/4 |
| vulnpy | FP 0/0 · TP 0/15 · unc 0/15 | FP 0/0 · TP 0/15 · unc 1/15 |
| dvga | FP 0/0 · TP 2/4 · unc 0/4 | FP 0/0 · TP 0/4 · unc 0/4 |
| ctfd | FP 2/3 · TP 0/0 · unc 0/3 | FP 2/3 · TP 0/0 · unc 0/3 |
| mealie | FP 9/13 · TP 1/2 · unc 0/15 | FP 11/13 · TP 1/2 · unc 1/15 |

True positives marked likely_harmless:

- ollama/qwen2.5-coder:7b: `vulpy-ssl.py::13::1` (GT-SECRET-001, vulpy-bad): The SECRET_KEY is hardcoded but appears to be a placeholder or dummy value.
- ollama/qwen2.5-coder:7b: `vulpy.py::16::1` (GT-SECRET-001, vulpy-bad): The SECRET_KEY is hardcoded but appears to be a placeholder or dummy value.
- ollama/qwen2.5-coder:7b: `libapi.py::10::1` (GT-SECRET-001, vulpy-good): The secret is hardcoded but only used in internal functions and not exposed to users.
- ollama/qwen2.5-coder:7b: `libsession.py::9::1` (GT-SECRET-001, vulpy-good): The secret is hardcoded but only used in test configuration, as indicated by the comment 'load it from the environment.'
- ollama/qwen2.5-coder:7b: `vulpy-ssl.py::13::1` (GT-SECRET-001, vulpy-good): The SECRET_KEY is hardcoded but does not appear to be used in a way that could be exploited by an attacker.
- ollama/qwen2.5-coder:7b: `vulpy.py::17::1` (GT-SECRET-001, vulpy-good): The SECRET_KEY is hardcoded and does not appear to be used in a way that could be exploited by an attacker.
- ollama/qwen2.5-coder:7b: `app/app.py::63::9` (GT-SECRET-001, vulnerable-flask-app): The hardcoded secret is used in a test fixture and does not come from a user input.
- ollama/qwen2.5-coder:7b: `app.py::14::1` (GT-SECRET-001, dvga): The SECRET_KEY is hardcoded but not used in a way that could be exploited by an attacker. It is set to a random value and not exposed through the application's interface.
- ollama/qwen2.5-coder:7b: `app.py::15::1` (GT-SECRET-001, dvga): The JWT_SECRET_KEY is hardcoded but not used in a way that could be exploited by an attacker. It is not used in SQL queries or shell commands, and it is not a secret that could be used to authenticate or authorize users.
- ollama/qwen2.5-coder:7b: `mealie/core/settings/settings.py::290::5` (GT-SECRET-001, mealie): The default password is hardcoded but not used in a way that could be exploited by an attacker. It is only used for initial setup and is not exposed in any user-facing interface.
- ollama/llama3.1:8b: `mealie/core/settings/db_providers.py::38::5` (GT-SECRET-001, mealie): The secret is hardcoded in the code, but it's only used for a PostgreSQL database connection, which is not a typical case for user input.
