"""
tests/test_reach_fixes.py — general reachability patterns, on small fixtures:

  1. Falcon routes: `app.add_route("/a", Resource())` and the resource's
     `on_get` / `on_post` / ... responders
  2. thread targets: `threading.Thread(target=f)` is a (dynamic) call to f

Run:  pytest tests/test_reach_fixes.py -v
"""

from __future__ import annotations

import textwrap

from gittrace.core.reachability import GraphReachability
from gittrace.core.scan import scan
from gittrace.graph.memstore import GraphStore
from gittrace.languages.base import SourceFile
from gittrace.languages.python import PythonPlugin


def _analyze(files: dict[str, str]):
    plugin = PythonPlugin()
    parsed = plugin.parse([SourceFile(p, textwrap.dedent(s).encode()) for p, s in files.items()])
    return plugin.resolve_calls(parsed), plugin.detect_routes(parsed)


def _endpoints(endpoints) -> dict[str, tuple]:
    return {e.id: (e.framework, e.auth_required, e.prefix_resolved) for e in endpoints}


def _scan(tmp_path, files: dict[str, str]) -> GraphStore:
    for path, source in files.items():
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(textwrap.dedent(source), encoding="utf-8")
    g = GraphStore("t")
    scan(tmp_path, blame=False, graph=g, graph_name=g.name)
    return g


class TestFalcon:
    FILES = {
        "res.py": """
            import falcon

            def require_auth(req, resp, resource, params):
                pass

            class Base:
                def on_get(self, req, resp):
                    pass

            class Items(Base):
                def on_post(self, req, resp):
                    pass

                def helper(self):
                    pass

            @falcon.before(require_auth)
            class Admin:
                def on_delete(self, req, resp):
                    pass

            class Things:
                def on_get(self, req, resp):
                    pass

                def on_get_one(self, req, resp, tid):
                    pass
        """,
        "app.py": """
            import falcon
            import falcon.asgi
            from res import Admin, Items, Things

            app = falcon.App()
            things = Things()
            app.add_route("/items", Items())
            app.add_route("/admin", Admin())
            app.add_route("/things", things)
            app.add_route("/things/{tid}", things, suffix="one")
            app.add_route(PATHS["x"], Items())
            legacy = falcon.API()
            legacy.add_route("/old", Items())
            aio = falcon.asgi.App()
            aio.add_route("/aio", Things())

            class Router:
                def add_route(self, *a, **k):
                    pass

            Router().add_route("/not-falcon", Items())
        """,
    }

    def test_responders_become_endpoints(self):
        _, endpoints = _analyze(self.FILES)
        assert _endpoints(endpoints) == {
            "GET /items -> res.py::Base.on_get": ("falcon", False, True),        # inherited responder
            "POST /items -> res.py::Items.on_post": ("falcon", False, True),
            "DELETE /admin -> res.py::Admin.on_delete": ("falcon", True, True),  # @falcon.before(require_auth)
            "GET /things -> res.py::Things.on_get": ("falcon", False, True),     # a variable holding an instance
            "GET /things/{tid} -> res.py::Things.on_get_one": ("falcon", False, True),   # suffix="one"
            'GET ${PATHS["x"]} -> res.py::Base.on_get': ("falcon", False, False),        # path kept, unresolved
            'POST ${PATHS["x"]} -> res.py::Items.on_post': ("falcon", False, False),
            "GET /old -> res.py::Base.on_get": ("falcon", False, True),          # falcon.API
            "POST /old -> res.py::Items.on_post": ("falcon", False, True),
            "GET /aio -> res.py::Things.on_get": ("falcon", False, True),        # falcon.asgi.App
        }

    def test_a_falcon_route_reaches_a_sink(self, tmp_path):
        g = _scan(tmp_path, {"app.py": """
            import os
            import falcon

            class Upload:
                def on_post(self, req, resp):
                    os.system("echo " + req.get_param("name"))

            app = falcon.App()
            app.add_route("/upload", Upload())
        """})
        (route,) = GraphReachability(g, 10).reach("app.py::Upload.on_post").routes
        assert route.nodes == ("POST /upload -> app.py::Upload.on_post", "app.py::Upload.on_post")
        assert route.auth_required is False


class TestThreadTarget:
    FILES = {"jobs.py": """
        import threading
        from threading import Thread as T

        def work(n):
            pass

        class Worker:
            def run(self):
                pass

            def go(self):
                threading.Thread(target=self.run).start()

        def spawn(n):
            threading.Thread(target=work, args=(n,)).start()

        def spawn_aliased():
            T(target=work).start()

        def spawn_positional():
            threading.Thread(None, work).start()

        def spawn_unknown(fn):
            threading.Thread(target=fn).start()
            threading.Thread(target=lambda: work(1)).start()
    """}

    def test_the_target_is_a_dynamic_call(self):
        calls, _ = _analyze(self.FILES)
        edges = {(c.caller_id, c.callee_id): c.dynamic for c in calls if c.callee_id}
        assert edges[("jobs.py::spawn", "jobs.py::work")] is True
        assert edges[("jobs.py::Worker.go", "jobs.py::Worker.run")] is True        # a bound method
        assert edges[("jobs.py::spawn_aliased", "jobs.py::work")] is True          # from threading import Thread as T
        assert edges[("jobs.py::spawn_positional", "jobs.py::work")] is True       # Thread(group, target)
        # A parameter or a lambda is not a known target: no thread edge is guessed.
        # (The lambda's own body, work(1), is an ordinary call of spawn_unknown.)
        assert not [c for c in calls if c.caller_id == "jobs.py::spawn_unknown" and c.dynamic]
        # The constructor call itself is still recorded, unresolved, as before.
        assert any(c.caller_id == "jobs.py::spawn" and c.dotted == "threading.Thread" and not c.dynamic
                   for c in calls)

    def test_a_route_reaches_a_sink_through_a_thread(self, tmp_path):
        g = _scan(tmp_path, {"app.py": """
            import os
            import threading
            from flask import Flask, request

            app = Flask(__name__)

            def work(cmd):
                os.system("echo " + cmd)

            @app.route("/run")
            def run():
                threading.Thread(target=work, args=(request.args["c"],)).start()
                return "ok"
        """})
        (route,) = GraphReachability(g, 10).reach("app.py::work").routes
        assert route.nodes == ("GET /run -> app.py::run", "app.py::run", "app.py::work")
        assert g.g.edges[("Function", "app.py::run"), ("Function", "app.py::work")]["props"]["dynamic"] is True
