"""
test_getattr_graph.py — getattr dispatch end to end: a real scan writes the
dynamic CALLS edges into the graph store, routes reach through them, and they
persist in <project>/.gittrace/graph.json.

tests/test_getattr_dispatch.py checks the resolver's CallSites; this checks
what the graph keeps of them.

Run:  pytest tests/test_getattr_graph.py -v
"""

from __future__ import annotations

import textwrap

from gittrace.core.reachability import GraphReachability
from gittrace.core.scan import scan
from gittrace.graph.memstore import GraphStore

APP = """
    import os

    from flask import Flask

    app = Flask(__name__)


    class Ops:
        def ping(self, name):
            return name

        def wipe(self, name):
            os.system("rm -rf /tmp/" + name)


    @app.route("/op/<name>")
    def op(name):
        ops = Ops()
        return getattr(ops, name)(name)
"""


def _calls(g: GraphStore) -> dict[tuple[str, str], dict]:
    return {(a[1], b[1]): d["props"] for a, b, d in g.g.edges(data=True) if d["type"] == "CALLS"}


def test_dispatch_on_a_variable_receiver_is_kept_in_the_graph_and_its_cache(tmp_path):
    (tmp_path / "app.py").write_text(textwrap.dedent(APP), encoding="utf-8")
    result = scan(tmp_path, blame=False)

    g = GraphStore.load(tmp_path)                      # the cache written by the scan
    calls = _calls(g)
    for member in ("app.py::Ops.ping", "app.py::Ops.wipe"):
        assert calls[("app.py::op", member)]["dynamic"] is True
    assert not any(p["dynamic"] for (a, _), p in calls.items() if a != "app.py::op")

    (route,) = GraphReachability(g, 10).reach("app.py::Ops.wipe").routes
    assert route.nodes == ("GET /op/<name> -> app.py::op", "app.py::op", "app.py::Ops.wipe")
    assert route.auth_required is False

    (finding,) = [f for f in result.findings if f.function_id == "app.py::Ops.wipe"]
    assert finding.reachable and finding.unauthenticated
