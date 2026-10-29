"""
expected_findings — what `gittrace scan` must report for tests/fixtures/sample_app.

Written by hand from the fixture source and the severity model in
gittrace.core.severity (base: high 6, medium 4; unauthenticated +3,
authenticated only +1, unreachable -2, parameter-derived +1, blast radius >= 5
+1; >= 9 critical, 7-8 high, 4-6 medium). Shared by tests/test_scan.py
(offline) and tests/test_scan_integration.py (the graph store).
"""

LIST_FILES = "GET /api/users/{name}/files -> app/routers/users.py::list_files"

# id -> (rule_id, severity, score, function, params, [(endpoint, hops)], callers, uncertain)
FINDINGS = {
    # f-string SQL from `name`; reached from an unauthenticated and an
    # authenticated route; 3 callers + 2 endpoints = blast radius 5.
    # 6 + 3 + 1 + 1 = 11
    "app/db.py::17::9": (
        "GT-SQLI-001", "critical", 11, "app/db.py::Repo.get_user", ("name",),
        [("GET /api/users/{name} -> app/routers/users.py::read_user", 1),
         ("GET /me -> app/main.py::me", 1)],
        ("app/db.py::AuditRepo.get_user", "app/main.py::me", "app/routers/users.py::read_user"),
        False),
    # os.popen(cmd) on a router that is never included: reachable, but every
    # deciding route has an unresolved prefix. 6 + 3 + 1 = 10
    "app/routers/debug.py::16::12": (
        "GT-CMDI-001", "critical", 10, "app/routers/debug.py::run", ("cmd",),
        [("GET /debug/run -> app/routers/debug.py::run", 0)], (), True),
    # sql = "..." + user_id + "'"; sql += " ORDER BY " + order. 6 + 3 + 1 = 10
    "app/routers/reports.py::16::12": (
        "GT-SQLI-001", "critical", 10, "app/routers/reports.py::by_user", ("order", "user_id"),
        [("GET /api/reports/by-user -> app/routers/reports.py::by_user", 0)], (), False),
    # yaml.load(body) with no Loader. 6 + 3 + 1 = 10
    "app/routers/reports.py::33::12": (
        "GT-DESER-001", "critical", 10, "app/routers/reports.py::import_report", ("body",),
        [("POST /api/reports/import -> app/routers/reports.py::import_report", 0)], (), False),
    # sp.check_output("ping -c 1 " + name, shell=True). 6 + 3 + 1 = 10
    "app/routers/users.py::27::14": (
        "GT-CMDI-001", "critical", 10, "app/routers/users.py::ping_user", ("name",),
        [("GET /api/users/{name}/ping -> app/routers/users.py::ping_user", 0)], (), False),
    # os.system("logger " + msg) in a nested function, two calls from the route.
    "app/utils/shell.py::8::9": (
        "GT-CMDI-001", "critical", 10, "app/utils/shell.py::run_command.log", ("msg",),
        [(LIST_FILES, 2)],
        ("app/routers/users.py::list_files", "app/utils/shell.py::run_command"), False),
    # run(cmd, shell=True) with cmd a parameter (from subprocess import run).
    "app/utils/shell.py::11::12": (
        "GT-CMDI-001", "critical", 10, "app/utils/shell.py::run_command", ("cmd",),
        [(LIST_FILES, 1)], ("app/routers/users.py::list_files",), False),
    # eval(expr) on the admin router, which requires auth. 6 + 1 + 1 = 8
    "app/routers/admin.py::11::23": (
        "GT-EVAL-001", "high", 8, "app/routers/admin.py::run_expression", ("expr",),
        [("POST /api/admin/eval -> app/routers/admin.py::run_expression", 0)], (), False),
    # "... %s" % days through `query`; only cron's nightly() calls it. 6 - 2 + 1 = 5
    "app/services/maintenance.py::19::5": (
        "GT-SQLI-001", "medium", 5, "app/services/maintenance.py::purge", ("days",),
        [], ("app/services/maintenance.py::nightly",), False),
    # pickle.load(fh), fh from `with open(path, "rb") as fh`. 6 - 2 + 1 = 5
    "app/services/maintenance.py::29::16": (
        "GT-DESER-001", "medium", 5, "app/services/maintenance.py::load_cache", ("path",),
        [], (), False),
    # Hardcoded secrets: base medium, never adjusted for reachability. 4
    "app/auth.py::4::1": (
        "GT-SECRET-001", "medium", 4, "app/auth.py::<module>", (), [], (), False),
    "app/routers/reports.py::8::1": (
        "GT-SECRET-001", "medium", 4, "app/routers/reports.py::<module>", (), [], (), False),
    "app/services/maintenance.py::42::9": (
        "GT-SECRET-001", "medium", 4, "app/services/maintenance.py::Mailer.__init__", (), [], (), False),
}

# Display order: severity, then score, then unauthenticated/reachable first, then location.
ORDER = list(FINDINGS)

# The full route for the deepest path, node by node.
SHELL_LOG_PATH = (
    LIST_FILES,
    "app/routers/users.py::list_files",
    "app/utils/shell.py::run_command",
    "app/utils/shell.py::run_command.log",
)

# Planted non-findings: (file, line, why it must not be reported).
NOT_FINDINGS = [
    ("app/routers/reports.py", 22, "constant SQL"),
    ("app/routers/reports.py", 28, "parameterised query"),
    ("app/routers/reports.py", 38, "eval of a constant"),
    ("app/services/maintenance.py", 7, "secret read from the environment"),
    ("app/services/maintenance.py", 8, "secret read from the environment"),
    ("app/services/maintenance.py", 9, "a name describing a secret field"),
    ("app/services/maintenance.py", 10, "placeholder password"),
    ("app/services/maintenance.py", 14, "constant SQL"),
    ("app/services/maintenance.py", 33, "yaml.load with SafeLoader"),
    ("app/services/maintenance.py", 37, "eval of a constant"),
    # Known false negative: the query is built in build_query() and passed in
    # as a call result; the rules do not follow values across calls.
    ("app/db.py", 24, "SQL built in another function (not followed)"),
]

SUMMARY = {
    "total": 13,
    "by_severity": {"critical": 7, "high": 1, "medium": 5, "low": 0, "info": 0},
    "by_rule": {"GT-CMDI-001": 4, "GT-DESER-001": 2, "GT-EVAL-001": 1, "GT-SECRET-001": 3,
                "GT-SQLI-001": 3},
    "reachable": 8,
    "unauthenticated": 7,
}
