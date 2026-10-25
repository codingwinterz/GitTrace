"""
expected_sample_app — what ingesting tests/fixtures/sample_app must produce.

Written by hand from the fixture source (line numbers included), not captured
from the ingester's output. Shared by the offline suite (tests/test_ingest.py)
and the FalkorDB suite (tests/test_ingest_integration.py).
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parent / "fixtures" / "sample_app"

FILES = [
    "app/__init__.py",
    "app/auth.py",
    "app/db.py",
    "app/main.py",
    "app/routers/__init__.py",
    "app/routers/admin.py",
    "app/routers/debug.py",
    "app/routers/users.py",
    "app/utils/__init__.py",
    "app/utils/shell.py",
]

FAILURES = [("scripts/half_merged.py", "syntax error at line 3")]

# id -> (kind, start_line, end_line, is_async)
FUNCTIONS = {
    "app/auth.py::<module>": ("module", 1, 10, False),
    "app/auth.py::get_current_user": ("function", 7, 10, False),
    "app/db.py::connect": ("function", 7, 8, False),
    "app/db.py::Repo.__init__": ("method", 12, 13, False),
    "app/db.py::Repo.get_user": ("method", 15, 18, False),
    "app/db.py::Repo.delete_user": ("method", 20, 25, False),
    "app/db.py::Repo.delete_user.build_query": ("nested", 21, 22, False),
    "app/db.py::Repo._log": ("method", 27, 28, False),
    "app/db.py::AuditRepo.get_user": ("method", 32, 34, False),
    "app/main.py::<module>": ("module", 1, 21, False),
    "app/main.py::health": ("function", 13, 15, False),
    "app/main.py::me": ("function", 18, 21, False),
    "app/routers/admin.py::<module>": ("module", 1, 23, False),
    "app/routers/admin.py::run_expression": ("function", 9, 11, False),
    "app/routers/admin.py::report": ("function", 14, 19, False),
    "app/routers/admin.py::report.render": ("nested", 16, 17, False),
    "app/routers/admin.py::load_rows": ("function", 22, 23, False),
    "app/routers/debug.py::<module>": ("module", 1, 11, False),
    "app/routers/debug.py::dump_env": ("function", 9, 11, False),
    "app/routers/users.py::<module>": ("module", 1, 33, False),
    "app/routers/users.py::read_user": ("function", 12, 15, False),
    "app/routers/users.py::remove_user": ("function", 18, 22, False),
    "app/routers/users.py::ping_user": ("function", 25, 28, True),
    "app/routers/users.py::list_files": ("function", 31, 33, False),
    "app/utils/shell.py::run_command": ("function", 6, 11, False),
    "app/utils/shell.py::run_command.log": ("nested", 7, 8, False),
}

# (caller, callee, line) — calls that resolve to project functions.
RESOLVED = {
    # same-file function
    ("app/db.py::Repo.__init__", "app/db.py::connect", 13),
    # nested function, and self.method()
    ("app/db.py::Repo.delete_user", "app/db.py::Repo.delete_user.build_query", 24),
    ("app/db.py::Repo.delete_user", "app/db.py::Repo._log", 25),
    # self.method() inherited from a project base class, and super()
    ("app/db.py::AuditRepo.get_user", "app/db.py::Repo._log", 33),
    ("app/db.py::AuditRepo.get_user", "app/db.py::Repo.get_user", 34),
    # `from app import Repo`, re-exported by app/__init__.py; repo = Repo()
    ("app/main.py::me", "app/db.py::Repo.__init__", 20),
    ("app/main.py::me", "app/db.py::Repo.get_user", 21),
    # nested function, and a module function defined later in the file
    ("app/routers/admin.py::report", "app/routers/admin.py::report.render", 19),
    ("app/routers/admin.py::report", "app/routers/admin.py::load_rows", 19),
    # `from ..db import Repo as Repository`
    ("app/routers/users.py::read_user", "app/db.py::Repo.__init__", 14),
    ("app/routers/users.py::read_user", "app/db.py::Repo.get_user", 15),
    ("app/routers/users.py::remove_user", "app/db.py::Repo.__init__", 20),
    ("app/routers/users.py::remove_user", "app/db.py::Repo.delete_user", 21),
    # `from ..utils.shell import run_command`
    ("app/routers/users.py::list_files", "app/utils/shell.py::run_command", 33),
    ("app/utils/shell.py::run_command", "app/utils/shell.py::run_command.log", 10),
}

# (caller, full dotted name, origin, line) — calls left unresolved.
UNRESOLVED = {
    ("app/auth.py::<module>", "fastapi.Header", "import", 7),
    ("app/auth.py::get_current_user", "fastapi.HTTPException", "import", 9),
    ("app/db.py::connect", "sqlite3.connect", "import", 8),
    ("app/db.py::Repo.get_user", "self.conn.cursor", "unknown", 16),
    ("app/db.py::Repo.get_user", "cursor.execute", "unknown", 17),
    ("app/db.py::Repo.get_user", "cursor.fetchone", "unknown", 18),
    ("app/db.py::Repo.delete_user.build_query", "str", "builtin", 22),
    ("app/db.py::Repo.delete_user", "self.conn.execute", "unknown", 24),
    ("app/db.py::Repo._log", "print", "builtin", 28),
    ("app/db.py::AuditRepo.get_user", "super", "builtin", 34),
    ("app/main.py::<module>", "fastapi.FastAPI", "import", 8),
    ("app/main.py::<module>", "app.include_router", "unknown", 9),
    ("app/main.py::<module>", "app.include_router", "unknown", 10),
    ("app/main.py::<module>", "app.get", "unknown", 13),
    ("app/main.py::<module>", "app.get", "unknown", 18),
    ("app/main.py::<module>", "fastapi.Depends", "import", 19),
    ("app/routers/admin.py::<module>", "fastapi.APIRouter", "import", 6),
    ("app/routers/admin.py::<module>", "fastapi.Depends", "import", 6),
    ("app/routers/admin.py::<module>", "router.post", "unknown", 9),
    ("app/routers/admin.py::run_expression", "eval", "builtin", 11),
    ("app/routers/admin.py::<module>", "router.api_route", "unknown", 14),
    ("app/routers/admin.py::report.render", "<string>.join", "unknown", 17),
    ("app/routers/admin.py::report.render", "str", "builtin", 17),
    ("app/routers/debug.py::<module>", "fastapi.APIRouter", "import", 6),
    ("app/routers/debug.py::<module>", "router.get", "unknown", 9),
    ("app/routers/debug.py::dump_env", "dict", "builtin", 11),
    ("app/routers/users.py::<module>", "fastapi.APIRouter", "import", 9),
    ("app/routers/users.py::<module>", "router.get", "unknown", 12),
    ("app/routers/users.py::<module>", "router.post", "unknown", 18),
    ("app/routers/users.py::<module>", "router.get", "unknown", 25),
    # `import subprocess as sp` -> sp.check_output
    ("app/routers/users.py::ping_user", "subprocess.check_output", "import", 27),
    ("app/routers/users.py::ping_user", "output.decode", "unknown", 28),
    ("app/routers/users.py::<module>", "router.get", "unknown", 31),
    ("app/utils/shell.py::run_command.log", "os.system", "import", 8),
    # `from subprocess import run`
    ("app/utils/shell.py::run_command", "subprocess.run", "import", 11),
}

# id -> (method, path, handler, line, auth_required, auth_evidence, prefix_resolved)
_ADMIN_AUTH = ("Depends(get_current_user)",)
ENDPOINTS = {
    "GET /health -> app/main.py::health":
        ("GET", "/health", "app/main.py::health", 13, False, (), True),
    "GET /me -> app/main.py::me":
        ("GET", "/me", "app/main.py::me", 18, True, _ADMIN_AUTH, True),
    "GET /api/users/{name} -> app/routers/users.py::read_user":
        ("GET", "/api/users/{name}", "app/routers/users.py::read_user", 12, False, (), True),
    "POST /api/users/{user_id}/delete -> app/routers/users.py::remove_user":
        ("POST", "/api/users/{user_id}/delete", "app/routers/users.py::remove_user", 18, False, (), True),
    "GET /api/users/{name}/ping -> app/routers/users.py::ping_user":
        ("GET", "/api/users/{name}/ping", "app/routers/users.py::ping_user", 25, False, (), True),
    "GET /api/users/{name}/files -> app/routers/users.py::list_files":
        ("GET", "/api/users/{name}/files", "app/routers/users.py::list_files", 31, False, (), True),
    "POST /api/admin/eval -> app/routers/admin.py::run_expression":
        ("POST", "/api/admin/eval", "app/routers/admin.py::run_expression", 9, True, _ADMIN_AUTH, True),
    "GET /api/admin/report -> app/routers/admin.py::report":
        ("GET", "/api/admin/report", "app/routers/admin.py::report", 14, True, _ADMIN_AUTH, True),
    "POST /api/admin/report -> app/routers/admin.py::report":
        ("POST", "/api/admin/report", "app/routers/admin.py::report", 14, True, _ADMIN_AUTH, True),
    # debug.router is never included: its own prefix only, flagged unresolved.
    "GET /debug/env -> app/routers/debug.py::dump_env":
        ("GET", "/debug/env", "app/routers/debug.py::dump_env", 9, False, (), False),
}


def calls_edges() -> dict[tuple[str, str], list[int]]:
    """RESOLVED + UNRESOLVED as graph edges: (caller, callee node id) -> sorted lines."""
    edges: dict[tuple[str, str], set[int]] = {}
    for caller, callee, line in RESOLVED:
        edges.setdefault((caller, callee), set()).add(line)
    for caller, dotted, _origin, line in UNRESOLVED:
        edges.setdefault((caller, f"external::{dotted}"), set()).add(line)
    return {k: sorted(v) for k, v in edges.items()}
