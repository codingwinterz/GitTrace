# Triage results (after-tuning-1: first tuning round)

Prompt `triage-v2` (gittrace/llm sha256 `2e81bb76e048`); set `measured` (vulpy-bad, vulpy-good, vulnerable-flask-app, vulnpy, dvga, ctfd, mealie); GPU: NVIDIA GeForce RTX 5050 Laptop GPU, 8151 MiB; no cache.

| Model | Findings (TP / FP) | FP marked likely_harmless | **TP marked likely_harmless** | Uncertain | Errors | Retries | Fixes that apply | s / finding (mean, median, max) |
|---|---|---|---|---|---|---|---|---|
| ollama/qwen2.5-coder:7b | 52 (35 / 17) | 10/17 (59%) | **11/35 (31%)** | 1/52 (2%) | 0 | 0 | 27/30 offered | 2.33, 2.12, 4.26 |
| ollama/llama3.1:8b | 52 (35 / 17) | 13/17 (76%) | **5/35 (14%)** | 3/52 (6%) | 0 | 0 | 24/28 offered | 2.52, 2.25, 6.08 |

Verdicts by label:

| Model | Label | likely_real | uncertain | likely_harmless | error | mean adjustment |
|---|---|---|---|---|---|---|
| ollama/qwen2.5-coder:7b | TP | 23 | 1 | 11 | 0 | 0 |
| ollama/qwen2.5-coder:7b | FP | 7 | 0 | 10 | 0 | 0 |
| ollama/llama3.1:8b | TP | 28 | 2 | 5 | 0 | 0.4 |
| ollama/llama3.1:8b | FP | 3 | 1 | 13 | 0 | 0.12 |

Per target (FP marked harmless / TP marked harmless / uncertain):

| Target | ollama/qwen2.5-coder:7b | ollama/llama3.1:8b |
|---|---|---|
| vulpy-bad | FP 0/1 · TP 2/5 · unc 0/6 | FP 1/1 · TP 2/5 · unc 0/6 |
| vulpy-good | FP 0/0 · TP 4/5 · unc 0/5 | FP 0/0 · TP 1/5 · unc 0/5 |
| vulnerable-flask-app | FP 0/0 · TP 2/4 · unc 1/4 | FP 0/0 · TP 0/4 · unc 1/4 |
| vulnpy | FP 0/0 · TP 0/15 · unc 0/15 | FP 0/0 · TP 0/15 · unc 1/15 |
| dvga | FP 0/0 · TP 2/4 · unc 0/4 | FP 0/0 · TP 0/4 · unc 0/4 |
| ctfd | FP 2/3 · TP 0/0 · unc 0/3 | FP 2/3 · TP 0/0 · unc 0/3 |
| mealie | FP 8/13 · TP 1/2 · unc 0/15 | FP 10/13 · TP 2/2 · unc 1/15 |

True positives marked likely_harmless:

- ollama/qwen2.5-coder:7b: `vulpy-ssl.py::13::1` (GT-SECRET-001, vulpy-bad): The SECRET_KEY is a dummy value with one character repeated, which is considered harmless.
- ollama/qwen2.5-coder:7b: `vulpy.py::16::1` (GT-SECRET-001, vulpy-bad): The secret is a repeated character and is not a real credential or default password.
- ollama/qwen2.5-coder:7b: `libapi.py::10::1` (GT-SECRET-001, vulpy-good): The secret is hardcoded but does not appear to be used in a way that could be exploited by an attacker.
- ollama/qwen2.5-coder:7b: `libsession.py::9::1` (GT-SECRET-001, vulpy-good): The secret is hardcoded but does not appear to be used in a way that could be exploited by an attacker.
- ollama/qwen2.5-coder:7b: `vulpy-ssl.py::13::1` (GT-SECRET-001, vulpy-good): The SECRET_KEY is a dummy value with one character repeated, which is considered harmless.
- ollama/qwen2.5-coder:7b: `vulpy.py::17::1` (GT-SECRET-001, vulpy-good): The SECRET_KEY is a hardcoded secret, but it appears to be a dummy or test-only value given its length and character classes.
- ollama/qwen2.5-coder:7b: `app/app.py::28::1` (GT-SECRET-001, vulnerable-flask-app): The secret key is hardcoded but does not appear to be used in a way that could be exploited by an attacker.
- ollama/qwen2.5-coder:7b: `app/app.py::63::9` (GT-SECRET-001, vulnerable-flask-app): The hardcoded password is a dummy value used for demonstration purposes.
- ollama/qwen2.5-coder:7b: `app.py::14::1` (GT-SECRET-001, dvga): The SECRET_KEY is hardcoded but appears to be a dummy value (4 distinct characters, lower case). It is not used in a way that could be exploited by an attacker.
- ollama/qwen2.5-coder:7b: `app.py::15::1` (GT-SECRET-001, dvga): The JWT_SECRET_KEY is hardcoded but appears to be a dummy value (4 distinct lower case characters). It is not used in a way that could be exploited by an attacker.
- ollama/qwen2.5-coder:7b: `mealie/core/settings/settings.py::290::5` (GT-SECRET-001, mealie): The _DEFAULT_PASSWORD is a hardcoded secret, but it is not used in any user-facing code and is only used for initial setup. It is marked as a constant and does not come from user input.
- ollama/llama3.1:8b: `vulpy-ssl.py::13::1` (GT-SECRET-001, vulpy-bad): The secret value is masked and has only 3 characters kept, suggesting it's an obvious placeholder.
- ollama/llama3.1:8b: `vulpy.py::16::1` (GT-SECRET-001, vulpy-bad): The secret is hardcoded and only used for the Flask app's configuration.
- ollama/llama3.1:8b: `vulpy-ssl.py::13::1` (GT-SECRET-001, vulpy-good): The secret value is masked and has only 3 characters kept, suggesting it's an obvious placeholder.
- ollama/llama3.1:8b: `mealie/core/settings/db_providers.py::38::5` (GT-SECRET-001, mealie): The secret is hardcoded in the code, but it's not used in a way that could lead to a vulnerability. The password is used to build a PostgresDsn object, which is then used to construct a database URL. The password is quoted and used as part of the URL, which makes it unlikely to be used as a secret.
- ollama/llama3.1:8b: `mealie/core/settings/settings.py::290::5` (GT-SECRET-001, mealie): The password is hardcoded and used only for the first user created in the database, and it should no longer be set by end users.
