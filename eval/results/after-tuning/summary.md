# Evaluation results (after-tuning)

GitTrace `scan --offline`; Bandit 1.9.4, its findings in the same five categories only.

| Target | Tool | Ground truth | TP | FP (of which benign) | FN | Precision | Recall | TP reachable without auth |
|---|---|---|---|---|---|---|---|---|
| vulpy-bad | gittrace | 5 | 5 | 1 (1) | 0 | 83% | 100% | 3 |
| vulpy-bad | bandit | 5 | 5 | 2 (2) | 0 | 71% | 100% | n/a |
| vulpy-good | gittrace | 5 | 5 | 0 (0) | 0 | 100% | 100% | 0 |
| vulpy-good | bandit | 5 | 4 | 0 (0) | 1 | 100% | 80% | n/a |
| vulnerable-flask-app | gittrace | 6 | 4 | 0 (0) | 2 | 100% | 67% | 2 |
| vulnerable-flask-app | bandit | 6 | 6 | 1 (0) | 0 | 86% | 100% | n/a |
| vulnpy | gittrace | 15 | 15 | 0 (0) | 0 | 100% | 100% | 2 |
| vulnpy | bandit | 15 | 10 | 2 (2) | 5 | 83% | 67% | n/a |
| **overall** | gittrace | 31 | 29 | 1 (1) | 2 | 97% | 94% | 7 |
| **overall** | bandit | 31 | 25 | 5 (4) | 6 | 83% | 81% | n/a |

Real-world projects (GitTrace):

| Project | Files | Endpoints | Findings | Reachable | Unauthenticated | Reviewed FP rate | Bandit (same categories) |
|---|---|---|---|---|---|---|---|
| ctfd | 350 | 88 | 3 | 0 | 0 | 3/3 (100%) | 267 |
| mealie | 695 | 213 | 15 | 0 | 0 | 13/15 (87%) | 101 |
