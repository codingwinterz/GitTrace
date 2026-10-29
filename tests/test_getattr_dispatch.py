"""
test_getattr_dispatch.py — dynamic dispatch through getattr(obj, name)(...).

The call-graph builder resolves direct calls (`obj.method()`). An immediate
`getattr(receiver, name)(...)` is the same call with a computed callee; the
resolver resolves it instead of dropping it:

  - a string-literal name resolves exactly as `receiver.name()` would;
  - a computed name has no single target, so the members the receiver is
    known to hold become low-confidence `dynamic` edges, and a receiver
    that cannot be resolved leaves a marker instead of nothing.

Run:  pytest tests/test_getattr_dispatch.py -v
"""

from __future__ import annotations

import textwrap

from gittrace.languages.base import SourceFile
from gittrace.languages.python import PythonPlugin


def _dispatched(files: dict[str, str]):
    """(the dynamic-dispatch CallSites, every CallSite) for these sources."""
    plugin = PythonPlugin()
    parsed = plugin.parse([SourceFile(p, textwrap.dedent(s).encode()) for p, s in files.items()])
    sites = plugin.resolve_calls(parsed)
    return [s for s in sites if s.dynamic], sites


class TestLiteralName:
    def test_literal_string_dispatches_like_the_direct_method_call(self):
        dispatch, _ = _dispatched({
            "t.py": """
                class Repo:
                    def get(self):
                        pass

                    def via_direct(self):
                        self.get()

                    def via_getattr(self):
                        getattr(self, "get")()
            """,
        })
        direct = {"t.py::Repo.get"}
        assert {s.callee_id for s in dispatch} == direct
        assert all(s.origin == "project" and s.resolved for s in dispatch)

    def test_literal_name_resolves_a_module_function_through_an_import(self):
        dispatch, _ = _dispatched({
            "triggers.py": """
                def cmdi():
                    pass
            """,
            "route.py": """
                import triggers

                def handler():
                    getattr(triggers, "cmdi")()
            """,
        })
        assert [s.callee_id for s in dispatch] == ["triggers.py::cmdi"]

    def test_builtins_getattr_is_dispatched_too(self):
        dispatch, _ = _dispatched({
            "route.py": """
                import triggers

                def handler():
                    builtins.getattr(triggers, "cmdi")()
            """,
            "triggers.py": """
                def cmdi():
                    pass
            """,
        })
        assert [s.callee_id for s in dispatch] == ["triggers.py::cmdi"]


class TestComputedName:
    def test_variable_name_fans_out_over_the_instance_methods(self):
        dispatch, _ = _dispatched({
            "t.py": """
                class Handlers:
                    def cmdi(self):
                        pass

                    def xss(self):
                        pass

                    def __init__(self):
                        pass

                def route(h, name):
                    h = Handlers()
                    getattr(h, name)()
            """,
        })
        # __init__ is a dunder and not a dispatch candidate; cmdi and xss are.
        assert {s.callee_id for s in dispatch} == {"t.py::Handlers.cmdi", "t.py::Handlers.xss"}
        assert all(s.origin == "project" and s.resolved for s in dispatch)

    def test_variable_name_fans_out_over_the_module_functions(self):
        dispatch, _ = _dispatched({
            "triggers.py": """
                def cmdi():
                    pass


                def xss():
                    pass
            """,
            "route.py": """
                import triggers

                def handler(name):
                    getattr(triggers, name)()
            """,
        })
        assert {s.callee_id for s in dispatch} == {"triggers.py::cmdi", "triggers.py::xss"}

    def test_prefixed_string_fans_out_to_all_members(self):
        dispatch, _ = _dispatched({
            "t.py": """
                class Triggers:
                    def do_cmdi(self):
                        pass

                    def do_xss(self):
                        pass

                    def other(self):
                        pass

                def route(t, name):
                    t = Triggers()
                    getattr(t, "do_" + name)()
            """,
        })
        # The static prefix "do_" is not narrowed in this phase: every member
        # is a candidate, flagged dynamic.
        assert {s.callee_id for s in dispatch} == {"t.py::Triggers.do_cmdi",
                                                   "t.py::Triggers.do_xss",
                                                   "t.py::Triggers.other"}

    def test_too_many_candidates_becomes_a_marker_not_a_fan_out(self):
        methods = "\n".join(f"    def m{i}(self):\n        pass\n" for i in range(30))
        dispatch, _ = _dispatched({
            "t.py": f"""
                class Wide:
{methods}
                def route(name):
                    w = Wide()
                    getattr(w, name)()
            """,
        })
        assert len(dispatch) == 1
        assert dispatch[0].callee_id is None and dispatch[0].origin == "dynamic"
        assert "w" in dispatch[0].dotted and "name" in dispatch[0].dotted


class TestUnresolvedMarker:
    def test_unknown_receiver_with_a_computed_name_is_a_marker(self):
        dispatch, _ = _dispatched({
            "t.py": """
                def route():
                    getattr(unknown_var, "do_" + kind)()
            """,
        })
        assert len(dispatch) == 1
        assert dispatch[0].callee_id is None
        assert dispatch[0].origin == "dynamic"
        assert "unknown_var" in dispatch[0].dotted

    def test_unknown_receiver_with_a_literal_name_keeps_the_attempted_target(self):
        dispatch, _ = _dispatched({
            "t.py": """
                def route():
                    getattr(unknown_var, "do_cmdi")()
            """,
        })
        # As `unknown_var.do_cmdi()` would be: unresolved, best dotted name,
        # still flagged as dispatch.
        assert len(dispatch) == 1
        assert dispatch[0].callee_id is None
        assert dispatch[0].origin == "unknown"
        assert dispatch[0].dotted == "unknown_var.do_cmdi"
        assert dispatch[0].dynamic is True

    def test_unresolvable_receiver_expression_is_a_marker(self):
        dispatch, _ = _dispatched({
            "t.py": """
                def make():
                    pass


                def route():
                    getattr(make(), "whatever")()
            """,
        })
        # `make()` cannot be resolved to a type; the direct call to make()
        # itself still resolves normally.
        assert len(dispatch) == 1
        assert dispatch[0].origin == "dynamic" and dispatch[0].callee_id is None


class TestNotDispatched:
    def test_a_stored_getattr_is_not_a_dispatch(self):
        dispatch, all_sites = _dispatched({
            "t.py": """
                class Repo:
                    def get(self):
                        pass

                    def handler(self):
                        fetch = getattr(self, "get")
                        return fetch
            """,
        })
        # The getattr is not immediately invoked: an ordinary builtin call,
        # and no edge to Repo.get from the dispatch machinery.
        assert dispatch == []
        getattr_calls = [s for s in all_sites if s.dotted == "getattr"]
        assert len(getattr_calls) == 1
        assert getattr_calls[0].origin == "builtin"
        assert getattr_calls[0].callee_id is None

    def test_a_getattr_result_passed_across_functions_is_not_resolved(self):
        dispatch, _ = _dispatched({
            "t.py": """
                def get(name):
                    return getattr(obj, name)

                def route(name):
                    trigger = get(name)
                    trigger()
            """,
        })
        # Documented limit: the value flows through a return and a local, so
        # the call graph does not connect it to a target in this phase.
        assert dispatch == []
