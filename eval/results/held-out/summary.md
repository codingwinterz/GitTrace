# Evaluation results (held-out)

GitTrace `scan --offline`; Bandit 1.9.4, its findings in the same five categories only.

| Target | Tool | Ground truth | TP | FP (of which benign) | FN | Precision | Recall | TP reachable without auth |
|---|---|---|---|---|---|---|---|---|
| dvga | gittrace | 5 | 4 | 0 (0) | 1 | 100% | 80% | 1 |
| dvga | bandit | 5 | 4 | 1 (0) | 1 | 80% | 80% | n/a |
| **overall** | gittrace | 5 | 4 | 0 (0) | 1 | 100% | 80% | 1 |
| **overall** | bandit | 5 | 4 | 1 (0) | 1 | 80% | 80% | n/a |

Real-world projects (GitTrace):

| Project | Files | Endpoints | Findings | Reachable | Unauthenticated | Reviewed FP rate | Bandit (same categories) |
|---|---|---|---|---|---|---|---|
| open-webui | 291 | 602 | 29 | 9 | 9 | 27/29 (93%) | 69 |
