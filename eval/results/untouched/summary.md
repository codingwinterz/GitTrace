# Evaluation results (untouched)

GitTrace `scan --offline`; Bandit 1.9.4, its findings in the same five categories only.

| Target | Tool | Ground truth | TP | FP (of which benign) | FN | Precision | Recall | TP reachable without auth |
|---|---|---|---|---|---|---|---|---|
| vulpy-bad | gittrace | 5 | 3 | 2 (2) | 2 | 60% | 60% | 3 |
| vulpy-bad | bandit | 5 | 5 | 2 (2) | 0 | 71% | 100% | n/a |
| vulpy-good | gittrace | 5 | 2 | 0 (0) | 3 | 100% | 40% | 0 |
| vulpy-good | bandit | 5 | 4 | 0 (0) | 1 | 100% | 80% | n/a |
| vulnerable-flask-app | gittrace | 6 | 3 | 0 (0) | 3 | 100% | 50% | 2 |
| vulnerable-flask-app | bandit | 6 | 6 | 1 (0) | 0 | 86% | 100% | n/a |
| vulnpy | gittrace | 15 | 15 | 1 (1) | 0 | 94% | 100% | 2 |
| vulnpy | bandit | 15 | 10 | 2 (2) | 5 | 83% | 67% | n/a |
| **overall** | gittrace | 31 | 23 | 3 (3) | 8 | 88% | 74% | 7 |
| **overall** | bandit | 31 | 25 | 5 (4) | 6 | 83% | 81% | n/a |

Real-world projects (GitTrace):

| Project | Files | Endpoints | Findings | Reachable | Unauthenticated | Reviewed FP rate | Bandit (same categories) |
|---|---|---|---|---|---|---|---|
| ctfd | 350 | 88 | 10 | 0 | 0 | 10/10 (100%) | 267 |
| mealie | 695 | 213 | 65 | 0 | 0 | 63/65 (97%) | 101 |
