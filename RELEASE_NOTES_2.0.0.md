# GitTrace 2.0.0

GitTrace scans a Python web project and finds the dangerous code an HTTP route can actually reach. It shows the path from the route to the bug, who calls it, who last changed it, and asks a local model whether the finding is real.

2.0.0 rebuilds GitTrace as a command-line tool (`gittrace scan`, `gittrace explain`, an interactive mode, `doctor`, `up`, and the `gittrace-mcp` server). It supports Python only, with FastAPI, Flask and Flask-RESTful/RESTX routes.

    pipx install git+https://github.com/codingwinterz/GitTrace@v2.0.0

- **Detection is comparable to Bandit, not better**, in the same five categories. Untouched, GitTrace scored 88% precision and 74% recall against Bandit's 83% and 81%. On the held-out DVGA, both found 4 of 5.
- **Reachability:** of the 20 true positives that a route truly reaches, GitTrace marks 7 as reachable, and 0 wrongly.
- **Known weakness: many false positives on real projects.** After tuning, 3 of 3 findings on CTFd and 13 of 15 on mealie were false positives (27 of 29 on the held-out open-webui).
- The samples are small, so read these numbers as indications, not benchmarks. Details are in the README ("Results at a glance") and `eval/`.

The 1.0 web demo is kept in the [`v1.0.0`](https://github.com/codingwinterz/GitTrace/tree/v1.0.0) tag.
