"""
test_ingest.py — offline tests for Python ingestion (no database).

Covers:
  1. File discovery: skipped directories, virtualenvs, .gitignore (nested, negation)
  2. tests/fixtures/sample_app: exact functions, calls and endpoints
     (expected values in tests/expected_sample_app.py)
  3. tests/fixtures/flask_app: Flask routes, blueprint prefixes, auth decorators
  4. Resolver edge cases: scoping, shadowing, duplicates, cycles, layouts
  5. Graph naming and the `python -m gittrace scan` entry point

Run:  pytest tests/test_ingest.py -v
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

import expected_sample_app as expected
from gittrace.core import discover, pipeline
from gittrace.graph.store import graph_name_for
from gittrace.languages.base import SourceFile
from gittrace.languages.python import PythonPlugin

REPO_ROOT = Path(__file__).resolve().parents[1]
FLASK_ROOT = Path(__file__).resolve().parent / "fixtures" / "flask_app"


@pytest.fixture(scope="module")
def sample():
    return pipeline.analyze(expected.ROOT)


def _analyze_sources(files: dict[str, str]):
    plugin = PythonPlugin()
    parsed = plugin.parse([SourceFile(p, textwrap.dedent(s).encode()) for p, s in files.items()])
    return parsed, plugin.resolve_calls(parsed), plugin.detect_routes(parsed)


def _targets(calls) -> dict[tuple[str, int], str]:
    """(caller, line) -> callee id, or `ext:<dotted>` when unresolved. Only
    usable when each (caller, line) has one call."""
    return {(c.caller_id, c.line): c.callee_id or f"ext:{c.dotted}" for c in calls}


# ---------------------------------------------------------------------------
# 1. Discovery
# ---------------------------------------------------------------------------

class TestDiscovery:
    def _tree(self, root: Path, files: dict[str, str]) -> None:
        for rel, text in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")

    def test_skips_tool_dirs_and_gitignored_paths(self, tmp_path):
        self._tree(tmp_path, {
            "main.py": "",
            "pkg/mod.py": "",
            "pkg/notes.txt": "",
            ".git/hooks/x.py": "",
            "venv/lib/x.py": "",
            ".venv/lib/x.py": "",
            "node_modules/x/x.py": "",
            "pkg/__pycache__/x.py": "",
            "lib/site-packages/x.py": "",
            "build/x.py": "",
            "dist/x.py": "",
            "pkg.egg-info/x.py": "",
            # A virtualenv with an unusual name is recognised by pyvenv.cfg.
            "myenv/pyvenv.cfg": "home = /usr/bin",
            "myenv/lib/x.py": "",
            ".gitignore": "generated/\n*_pb2.py\n!keep_pb2.py\n",
            "generated/x.py": "",
            "pkg/api_pb2.py": "",
            "pkg/keep_pb2.py": "",
            # A nested .gitignore applies below its own directory only.
            "pkg/.gitignore": "local_*.py\n",
            "pkg/local_settings.py": "",
            "local_top.py": "",
        })
        assert discover.discover(tmp_path, (".py",)) == [
            "local_top.py",
            "main.py",
            "pkg/keep_pb2.py",
            "pkg/mod.py",
        ]

    def test_deeper_gitignore_overrides(self, tmp_path):
        self._tree(tmp_path, {
            ".gitignore": "*.gen.py\n",
            "a/.gitignore": "!wanted.gen.py\n",
            "a/wanted.gen.py": "",
            "a/other.gen.py": "",
        })
        assert discover.discover(tmp_path, (".py",)) == ["a/wanted.gen.py"]

    def test_sample_app_files(self, sample):
        assert sorted(f.path for f in sample.files) == expected.FILES


# ---------------------------------------------------------------------------
# 2. sample_app (FastAPI)
# ---------------------------------------------------------------------------

class TestSampleApp:
    def test_parse_failure_is_reported_and_skipped(self, sample):
        assert [(f.path, f.reason) for f in sample.failures] == expected.FAILURES
        assert not any(f.file == "scripts/half_merged.py" for f in sample.functions)

    def test_functions(self, sample):
        got = {f.id: (f.kind, f.start_line, f.end_line, f.is_async) for f in sample.functions}
        assert got == expected.FUNCTIONS

    def test_ids_are_path_and_qualified_name(self, sample):
        for f in sample.functions:
            assert f.id == f"{f.file}::{f.qualified_name}"
            assert not f.file.startswith("/") and "\\" not in f.file

    def test_source_spans_match_the_file(self, sample):
        for f in sample.functions:
            # read_text() turns CRLF into \n, as the ingester does for source.
            text = (expected.ROOT / f.file).read_text(encoding="utf-8")
            if f.kind == "module":
                assert f.source == text, f.id
            else:
                lines = text.splitlines()
                assert f.source == "\n".join(lines[f.start_line - 1:f.end_line]), f.id

    def test_crlf_source_is_normalised(self):
        plugin = PythonPlugin()
        parsed = plugin.parse([SourceFile("m.py", b"def f():\r\n    return 1\r\n")])
        assert [(f.source, f.end_line) for f in parsed.functions] == [("def f():\n    return 1", 2)]

    def test_decorated_source_includes_decorators(self, sample):
        me = next(f for f in sample.functions if f.id == "app/main.py::me")
        assert me.source.startswith('@app.get("/me")\ndef me(')

    def test_file_hashes(self, sample):
        for rec in sample.files:
            data = (expected.ROOT / rec.path).read_bytes()
            assert rec.sha256 == hashlib.sha256(data).hexdigest()
            assert rec.language == "python"

    def test_resolved_calls(self, sample):
        got = {(c.caller_id, c.callee_id, c.line) for c in sample.calls if c.resolved}
        assert got == expected.RESOLVED

    def test_unresolved_calls(self, sample):
        got = {(c.caller_id, c.dotted, c.origin, c.line) for c in sample.calls if not c.resolved}
        assert got == expected.UNRESOLVED

    def test_no_call_site_is_lost_or_duplicated(self, sample):
        assert len(sample.calls) == len(expected.RESOLVED) + len(expected.UNRESOLVED)

    def test_endpoints(self, sample):
        got = {e.id: (e.method, e.path, e.handler_id, e.line, e.auth_required,
                      e.auth_evidence, e.prefix_resolved) for e in sample.endpoints}
        assert got == expected.ENDPOINTS
        assert {e.framework for e in sample.endpoints} == {"fastapi"}

    def test_counts(self, sample):
        counts = sample.counts()
        assert counts["files"] == 13
        assert counts["parse_failures"] == 1
        assert counts["functions"] == 34
        assert counts["module_scopes"] == 7
        assert counts["endpoints"] == 16
        assert counts["calls"] == 82
        assert counts["resolved_calls"] == 20
        assert counts["unresolved_calls"] == 62
        assert counts["external_callees"] == 35


# ---------------------------------------------------------------------------
# 3. flask_app
# ---------------------------------------------------------------------------

class TestFlaskApp:
    def test_endpoints(self):
        result = pipeline.analyze(FLASK_ROOT)
        got = {e.id: (e.method, e.path, e.line, e.auth_required, e.auth_evidence, e.prefix_resolved)
               for e in result.endpoints}
        assert got == {
            "GET / -> app.py::index": ("GET", "/", 12, False, (), True),
            "GET /login -> app.py::login": ("GET", "/login", 17, False, (), True),
            "POST /login -> app.py::login": ("POST", "/login", 17, False, (), True),
            # register_blueprint(url_prefix="/u") replaces the blueprint's "/users".
            "GET /u/<int:uid> -> views.py::show": ("GET", "/u/<int:uid>", 9, False, (), True),
            "POST /u/import -> views.py::import_data": ("POST", "/u/import", 14, False, (), True),
            "GET /admin/stats -> admin.py::stats":
                ("GET", "/admin/stats", 8, True, ("@login_required",), True),
        }
        assert {e.framework for e in result.endpoints} == {"flask"}

    def test_sink_call_is_kept(self):
        result = pipeline.analyze(FLASK_ROOT)
        assert ("views.py::import_data", "pickle.loads", "import") in {
            (c.caller_id, c.dotted, c.origin) for c in result.calls
        }


# ---------------------------------------------------------------------------
# 4. Resolver edge cases
# ---------------------------------------------------------------------------

class TestResolver:
    def test_scoping_shadowing_and_duplicates(self):
        _, calls, _ = _analyze_sources({"m.py": """
            def helper(): pass
            def helper(): pass
            def shadowed(helper):
                helper()
            def uses_global():
                global helper
                helper()
            def local_import():
                import os.path as osp
                osp.join("a")
            def outer():
                def outer(): pass
                outer()
        """})
        t = _targets(calls)
        # The later def wins, and gets a distinct ID.
        assert t[("m.py::uses_global", 8)] == "m.py::helper#2"
        # A parameter shadows the module function.
        assert t[("m.py::shadowed", 5)] == "ext:helper"
        assert t[("m.py::local_import", 11)] == "ext:os.path.join"
        assert t[("m.py::outer", 14)] == "m.py::outer.outer"

    def test_classes(self):
        _, calls, _ = _analyze_sources({"m.py": """
            class Base:
                def run(self): pass
            class Child(Base):
                @classmethod
                def make(cls):
                    return cls.build()
                @staticmethod
                def build(): pass
                def go(self):
                    self.run()
                    Child.build()
                    Child().go()
                def __call__(self): pass
            c = Child()
            def use():
                c()
                Base()
        """})
        t = _targets(calls)
        assert t[("m.py::Child.make", 7)] == "m.py::Child.build"
        assert t[("m.py::Child.go", 11)] == "m.py::Base.run"
        assert t[("m.py::Child.go", 12)] == "m.py::Child.build"
        go13 = {c.callee_id for c in calls if c.caller_id == "m.py::Child.go" and c.line == 13}
        assert go13 == {"m.py::Child.go", None}       # Child().go() and Child()
        assert t[("m.py::use", 17)] == "m.py::Child.__call__"
        # A project class with no __init__ runs no project code: no edge.
        base = next(c for c in calls if c.caller_id == "m.py::use" and c.line == 18)
        assert (base.callee_id, base.origin) == (None, "class")

    def test_cycles_terminate(self):
        _, calls, _ = _analyze_sources({
            "pkg/__init__.py": "",
            "pkg/a.py": "from .b import x\nclass A(B): pass\nclass B(A):\n    def m(self): self.nope()\n"
                        "v = v\ndef f():\n    x()\n    v.go()\n",
            "pkg/b.py": "from .a import x\nfrom pkg.c import *\n",
            "pkg/c.py": "from pkg.b import *\n",
            "pkg/d.py": "from pkg.b import nothing\nnothing()\n",
        })
        t = _targets(calls)
        origins = {(c.caller_id, c.line): c.origin for c in calls}
        # import cycle a.x -> b.x -> a.x
        assert t[("pkg/a.py::f", 7)] == "ext:pkg.a.x"
        assert origins[("pkg/a.py::f", 7)] == "project"
        assert t[("pkg/a.py::f", 8)] == "ext:v.go"
        assert t[("pkg/a.py::B.m", 4)] == "ext:self.nope"
        # star-import cycle b <-> c
        assert t[("pkg/d.py::<module>", 2)] == "ext:pkg.b.nothing"

    def test_package_layouts(self):
        _, calls, _ = _analyze_sources({
            # src layout: `proj` is importable by its package name
            "src/proj/__init__.py": "",
            "src/proj/core.py": "def run(): pass\n",
            "src/proj/cli.py": "from proj.core import run\ndef main():\n    run()\n",
            # namespace package (no __init__.py), also inside a regular package
            "ns/mod.py": "def nsf(): pass\n",
            "uses_ns.py": "import ns.mod\nns.mod.nsf()\n",
            "src/proj/costs/service.py": "def total(): pass\n",
            "src/proj/views.py": "from proj.costs import service\ndef v():\n    service.total()\n",
            # two scripts directories with a util.py each
            "tools/a/util.py": "def tool(): pass\n",
            "tools/b/util.py": "def tool(): pass\n",
            "tools/a/run.py": "import util\nutil.tool()\n",
            "other/run.py": "import util\nutil.tool()\n",
        })
        t = _targets(calls)
        assert t[("src/proj/cli.py::main", 3)] == "src/proj/core.py::run"
        assert t[("uses_ns.py::<module>", 2)] == "ns/mod.py::nsf"
        assert t[("src/proj/views.py::v", 3)] == "src/proj/costs/service.py::total"
        # The nearer util.py wins; equally near candidates are not guessed.
        assert t[("tools/a/run.py::<module>", 2)] == "tools/a/util.py::tool"
        assert t[("other/run.py::<module>", 2)] == "ext:util.tool"

    def test_aliased_external_names_are_expanded(self):
        _, calls, _ = _analyze_sources({"m.py": """
            import subprocess as sp
            from os import system as run_shell
            import yaml
            def f(cmd, cursor):
                sp.Popen(cmd, shell=True)
                run_shell(cmd)
                yaml.load(cmd)
                cursor.execute(cmd)
                exec(cmd)
        """})
        assert {(c.dotted, c.origin) for c in calls} == {
            ("subprocess.Popen", "import"),
            ("os.system", "import"),
            ("yaml.load", "import"),
            ("cursor.execute", "unknown"),
            ("exec", "builtin"),
        }

    def test_unparseable_file_does_not_stop_others(self):
        parsed, _, _ = _analyze_sources({"bad.py": "def f(:\n", "good.py": "def g(): pass\n"})
        assert [f.path for f in parsed.failures] == ["bad.py"]
        assert [f.id for f in parsed.functions] == ["good.py::g"]

    def test_utf8_bom_is_accepted(self):
        plugin = PythonPlugin()
        parsed = plugin.parse([SourceFile("m.py", b"\xef\xbb\xbfdef f():\n    pass\n")])
        assert not parsed.failures
        assert [(f.id, f.start_line) for f in parsed.functions] == [("m.py::f", 1)]


class TestRoutes:
    def test_nested_routers_mounted_twice_and_factories(self):
        _, _, endpoints = _analyze_sources({
            "app/__init__.py": "",
            "app/api.py": """
                from fastapi import APIRouter, Security
                import fastapi
                api = APIRouter()
                items = APIRouter(prefix="/items")
                @items.get("/")
                def list_items(): pass
                @items.delete("/{i}", dependencies=[Security(scheme)])
                def delete_item(i): pass
                api.include_router(items, prefix="/v1")
                other = fastapi.APIRouter(prefix=PREFIX)
                @other.websocket("/ws")
                async def ws(): pass
            """,
            "app/main.py": """
                from fastapi import FastAPI
                from app.api import api, other
                from app import api as api_mod
                def create_app():
                    app = FastAPI()
                    app.include_router(api, prefix="/api")
                    app.include_router(api_mod.api, prefix="/again")
                    app.include_router(other)
                    @app.post("/inner")
                    def inner(): pass
                    return app
                class Cache:
                    def get(self, key): pass
                cache = Cache()
                @cache.get("/not-a-route")
                def not_a_route(): pass
            """,
        })
        got = {e.id: (e.auth_required, e.prefix_resolved) for e in endpoints}
        assert got == {
            "GET /api/v1/items/ -> app/api.py::list_items": (False, True),
            "GET /again/v1/items/ -> app/api.py::list_items": (False, True),
            "DELETE /api/v1/items/{i} -> app/api.py::delete_item": (True, True),
            "DELETE /again/v1/items/{i} -> app/api.py::delete_item": (True, True),
            # A non-literal prefix is shown as an expression and flagged.
            "WEBSOCKET ${PREFIX}/ws -> app/api.py::ws": (False, False),
            "POST /inner -> app/main.py::create_app.inner": (False, True),
        }

    def test_mounted_sub_app(self):
        _, _, endpoints = _analyze_sources({"main.py": """
            from fastapi import FastAPI
            from fastapi.staticfiles import StaticFiles
            app = FastAPI()
            api = FastAPI()
            frontend = FastAPI()
            @api.get("/healthcheck")
            def healthcheck(): pass
            @app.get("/top")
            def top(): pass
            app.mount("/api/v1", app=api)
            app.mount("/", frontend)
            frontend.mount("/static", StaticFiles(directory="static"))
        """})
        assert {e.id: e.prefix_resolved for e in endpoints} == {
            "GET /api/v1/healthcheck -> main.py::healthcheck": True,
            "GET /top -> main.py::top": True,
        }

    def test_auth_through_annotated_alias(self):
        _, _, endpoints = _analyze_sources({
            "deps.py": """
                from typing import Annotated
                from fastapi import Depends
                CurrentUser = Annotated[dict, Depends(get_current_user)]
                SessionDep = Annotated[object, Depends(get_session)]
                RequireAdmin = Depends(require_admin)
            """,
            "views.py": """
                from fastapi import APIRouter
                from deps import CurrentUser, SessionDep, RequireAdmin
                router = APIRouter()
                @router.get("/me")
                def me(user: CurrentUser): pass
                @router.get("/items")
                def items(db: SessionDep): pass
                @router.delete("/items")
                def wipe(_=RequireAdmin): pass
            """,
        })
        got = {e.path + " " + e.method: e.auth_evidence for e in endpoints}
        assert got == {
            "/me GET": ("Depends(get_current_user)",),
            "/items GET": (),
            "/items DELETE": ("Depends(require_admin)",),
        }

    def test_auth_evidence(self):
        _, _, endpoints = _analyze_sources({"m.py": """
            from typing import Annotated
            from fastapi import Depends, FastAPI
            app = FastAPI()
            @app.get("/a")
            def a(db=Depends(get_db)): pass
            @app.get("/b")
            def b(user: Annotated[dict, Depends(get_current_active_user)]): pass
            @app.get("/c")
            @requires_auth
            def c(): pass
            @app.get("/d", dependencies=[Depends(verify_api_key)])
            def d(): pass
        """})
        got = {e.path: e.auth_evidence for e in endpoints}
        assert got == {
            "/a": (),
            "/b": ("Depends(get_current_active_user)",),
            "/c": ("@requires_auth",),
            "/d": ("Depends(verify_api_key)",),
        }
        assert {e.path for e in endpoints if e.auth_required} == {"/b", "/c", "/d"}


# ---------------------------------------------------------------------------
# 5. Graph names and the entry point
# ---------------------------------------------------------------------------

class TestEntryPoint:
    def test_graph_name_is_stable_and_per_project(self):
        a = graph_name_for(expected.ROOT)
        assert a == graph_name_for(str(expected.ROOT) + "/")
        assert a.startswith("gittrace_sample_app_")
        assert a != graph_name_for(FLASK_ROOT)

    def _scan(self, path) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "gittrace", "scan", str(path), "--offline", "--no-blame", "--no-llm",
             "--format", "json", "--fail-on", "none"],
            cwd=REPO_ROOT, capture_output=True, text=True, encoding="utf-8", timeout=120,
        )

    def test_scan_reports_what_was_ingested(self):
        out = self._scan(expected.ROOT)
        assert out.returncode == 0, out.stderr
        data = json.loads(out.stdout)
        assert data["scanned"] == {"files": 13, "parse_failures": 1, "functions": 34,
                                   "endpoints": 16, "calls": 82}
        assert data["parse_failures"] == [
            {"file": "scripts/half_merged.py", "reason": "syntax error at line 3"}]
        assert "half_merged.py" in out.stderr     # logged as a warning too

    def test_missing_path_is_an_error(self, tmp_path):
        out = self._scan(tmp_path / "nope")
        assert out.returncode == 2
        assert "not a directory" in out.stderr
