"""
gittrace.languages.python.routes — FastAPI and Flask route detection.

A decorator counts as a route only when the object it hangs off resolves (via
the resolver, across files) to a variable built by a known constructor:
fastapi.FastAPI / fastapi.APIRouter, flask.Flask / flask.Blueprint. A
`@cache.get(...)` on some other object is never mistaken for a route.

Prefixes:
  - FastAPI: app.include_router(router, prefix=...) + APIRouter(prefix=...)
    + the route path, concatenated as FastAPI does; routers included into
    routers are followed, and so is a FastAPI app mounted in another
    (`app.mount("/api/v1", api)`).
  - Flask: app.register_blueprint(bp, url_prefix=...) overrides
    Blueprint(url_prefix=...), as in Flask; nested blueprints are followed.
  A router that is never included (or a non-literal prefix) still yields its
  endpoints, with `prefix_resolved=False` and the prefix it does know.

Flask-RESTful / Flask-RESTX (and Flask-RESTPlus) resources: a class
registered with `api.add_resource(Cls, "/a", "/b")` or decorated with
`@api.route("/a")` / `@ns.route("/a")` is an endpoint per URL for each of
its HTTP-verb methods (`get`, `post`, ..., inherited from project base
classes too); the handler is the method. Prefixes: the app or blueprint
given to `Api(app, prefix=...)` or `api.init_app(app)`, then the Api's own
prefix; a Namespace's `path` (default "/<name>"), replaced by
`api.add_namespace(ns, path=...)`.

auth_required is true only on obvious evidence: a FastAPI dependency
(route, router, include_router or app level, or in the handler's parameters,
directly or through an alias such as
`CurrentUser = Annotated[User, Depends(get_current_user)]`) whose target is
named like auth, any `Security(...)`, or a handler decorator named like auth
(`@login_required`, `@jwt_required()`, ...), including a resource class's
`method_decorators` / `decorators` list, or a check at the top of the
handler's own body (its first parser.TOP_STATEMENTS statements): a
token-verifying call (`jwt.decode`, `verify_jwt_in_request()`, a function
named like `verify_token` / `check_auth`; not `login()` or
`authenticate()`, which a login handler calls) or a guard rejecting with
401/403. Checks in functions the handler calls are not followed. Default
false.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from gittrace.languages.base import EndpointDef, endpoint_id
from gittrace.languages.python.parser import PyFunction, PyModule, Value
from gittrace.languages.python.resolver import ClassSym, ExtInst, FuncSym, Resolver, VarSym

FASTAPI_APPS = frozenset({"fastapi.FastAPI", "fastapi.applications.FastAPI"})
FASTAPI_ROUTERS = frozenset({"fastapi.APIRouter", "fastapi.routing.APIRouter"})
FLASK_APPS = frozenset({"flask.Flask", "flask.app.Flask"})
FLASK_BLUEPRINTS = frozenset({"flask.Blueprint", "flask.blueprints.Blueprint"})
RESOURCE_APIS = frozenset({"flask_restful.Api", "flask_restx.Api", "flask_restx.api.Api",
                           "flask_restplus.Api", "flask_restplus.api.Api"})
RESOURCE_NAMESPACES = frozenset({"flask_restx.Namespace", "flask_restx.namespace.Namespace",
                                 "flask_restplus.Namespace", "flask_restplus.namespace.Namespace"})

_FASTAPI_VERBS = frozenset({"get", "post", "put", "delete", "patch", "options", "head", "trace"})
_FLASK_VERBS = frozenset({"get", "post", "put", "delete", "patch"})
_RESOURCE_VERBS = ("get", "post", "put", "patch", "delete", "head", "options")
_RESOURCE_DECORATOR_LISTS = ("method_decorators", "decorators")

AUTH_NAME = re.compile(
    r"auth|current_user|current_active_user|logged_in|login|token|jwt|oauth|bearer"
    r"|api_?key|permission|require|admin|verify",
    re.IGNORECASE,
)
# A call at the top of a handler that checks a token. Narrower than AUTH_NAME on
# purpose: a login handler calls login() / authenticate() and is still open.
VERIFY_CALLS = frozenset({"jwt.decode", "jose.jwt.decode", "flask_jwt_extended.verify_jwt_in_request",
                          "flask_jwt_extended.view_decorators.verify_jwt_in_request"})
VERIFY_NAME = re.compile(
    r"^(verify|validate|check|require|ensure)_?(jwt|(access_|auth_|bearer_|id_)?token|auth\w*"
    r"|api_?key|permissions?|admin|access)$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class RouteObject:
    var: VarSym
    framework: str        # fastapi | flask
    is_root: bool         # an app, not a router/blueprint
    ctor: Value
    kind: str = "router"  # app | router (APIRouter, Blueprint) | api | namespace (Flask-RESTful/RESTX)

    @property
    def resources(self) -> bool:
        return self.kind in ("api", "namespace")

    def own_prefix(self) -> Value | None:
        if self.kind == "api":
            return self.ctor.kwarg("prefix")
        if self.kind == "namespace":
            path = self.ctor.kwarg("path")
            name = self.ctor.args[0] if self.ctor.args else self.ctor.kwarg("name")
            if path is None and name is not None and name.kind == "str":
                return Value("str", name.text, name.line, string="/" + (name.string or ""))
            return path
        return self.ctor.kwarg("url_prefix" if self.framework == "flask" else "prefix")


@dataclass(frozen=True)
class _Mount:
    parent: RouteObject
    prefix: Value | None
    dependencies: tuple[Value, ...]


@dataclass(frozen=True)
class _Chain:
    prefix: str
    dependencies: tuple[Value, ...]
    resolved: bool


def _literal(value: Value | None) -> tuple[str, bool]:
    if value is None:
        return "", True
    if value.kind == "str":
        return value.string or "", True
    return f"${{{value.text}}}", False


def _items(value: Value | None) -> tuple[Value, ...]:
    if value is None or value.kind != "list":
        return ()
    return value.items


def flask_join(prefix: str, rule: str) -> str:
    if not prefix:
        return rule
    if not rule:
        return prefix
    return f"{prefix.rstrip('/')}/{rule.lstrip('/')}"


class _Detector:
    def __init__(self, modules: list[PyModule], resolver: Resolver):
        self.modules = modules
        self.resolver = resolver
        self.mounts: dict[VarSym, list[_Mount]] = {}
        self.functions: dict[str, PyFunction] = {fn.record.id: fn for mod in modules for fn in mod.functions}
        self.module_of: dict[str, PyModule] = {fn.record.id: mod for mod in modules for fn in mod.functions}
        self.calls_by_caller: dict[str, list] = {}
        for mod in modules:
            for call in mod.calls:
                self.calls_by_caller.setdefault(call.caller_id, []).append(call)

    def body_evidence(self, fn: PyFunction) -> list[str]:
        """Auth checked at the top of the handler's own body: a token-verifying
        call (VERIFY_CALLS, or a function named like VERIFY_NAME) or a guard
        that rejects with 401/403 (parser._top_of_body)."""
        found = [f"in body: {g}" for g in fn.body_guards]
        mod = self.module_of[fn.record.id]
        for call in self.calls_by_caller.get(fn.record.id, []):
            if call.call.line > fn.top_end_line:
                continue
            name = self.resolver.resolve_ref(mod, call.scope, call.call.parts).name
            if name in VERIFY_CALLS or VERIFY_NAME.match(name.split(".")[-1]):
                found.append(f"in body: {name}()")
        return found

    def route_object(self, mod: PyModule, scope, parts: tuple[str, ...]) -> RouteObject | None:
        sym = self.resolver.resolve_ref(mod, scope, parts).sym
        if not isinstance(sym, VarSym):
            return None
        held = self.resolver.deref(sym)
        ctor = self.resolver.assignment(sym)
        if not isinstance(held, ExtInst) or ctor is None:
            return None
        if held.dotted in FASTAPI_APPS:
            return RouteObject(sym, "fastapi", True, ctor, "app")
        if held.dotted in FASTAPI_ROUTERS:
            return RouteObject(sym, "fastapi", False, ctor)
        if held.dotted in FLASK_APPS:
            return RouteObject(sym, "flask", True, ctor, "app")
        if held.dotted in FLASK_BLUEPRINTS:
            return RouteObject(sym, "flask", False, ctor)
        if held.dotted in RESOURCE_APIS:
            return RouteObject(sym, "flask", False, ctor, "api")
        if held.dotted in RESOURCE_NAMESPACES:
            return RouteObject(sym, "flask", False, ctor, "namespace")
        return None

    def _flask_parent(self, mod: PyModule, scope, ref: Value | None) -> RouteObject | None:
        if ref is None or ref.kind != "ref":
            return None
        parent = self.route_object(mod, scope, ref.parts)
        return parent if parent is not None and parent.framework == "flask" and not parent.resources else None

    def collect_mounts(self) -> None:
        for mod in self.modules:
            for call in mod.calls:
                parts = call.call.parts
                verb = parts[-1]
                c = call.call
                if verb == "init_app" and len(parts) >= 2:
                    # api.init_app(app): as Api(app) (see chains), set up later.
                    api = self.route_object(mod, call.scope, parts[:-1])
                    parent = self._flask_parent(mod, call.scope, c.args[0] if c.args else c.kwarg("app"))
                    if api is not None and api.kind == "api" and parent is not None:
                        self.mounts.setdefault(api.var, []).append(_Mount(parent, None, ()))
                    continue
                if len(parts) < 2 or verb not in ("include_router", "register_blueprint", "mount",
                                                  "add_namespace"):
                    continue
                parent = self.route_object(mod, call.scope, parts[:-1])
                if parent is None:
                    continue
                if verb == "add_namespace":
                    # api.add_namespace(ns, path="/x"): the path replaces the namespace's own.
                    child_ref = c.args[0] if c.args else c.kwarg("ns")
                    child = (self.route_object(mod, call.scope, child_ref.parts)
                             if child_ref is not None and child_ref.kind == "ref" else None)
                    if parent.kind == "api" and child is not None and child.kind == "namespace":
                        prefix = c.args[1] if len(c.args) > 1 else c.kwarg("path")
                        self.mounts.setdefault(child.var, []).append(_Mount(parent, prefix, ()))
                    continue
                if parent.resources:
                    continue
                if verb == "mount":
                    # app.mount("/api/v1", sub_app): a FastAPI app under a path.
                    # Dependencies do not carry over into a mounted app.
                    if parent.framework != "fastapi":
                        continue
                    child_ref = c.args[1] if len(c.args) > 1 else c.kwarg("app")
                    prefix = c.args[0] if c.args else c.kwarg("path")
                    deps: tuple[Value, ...] = ()
                else:
                    flask = verb == "register_blueprint"
                    child_ref = c.args[0] if c.args else c.kwarg("blueprint" if flask else "router")
                    prefix = c.kwarg("url_prefix" if flask else "prefix")
                    deps = _items(c.kwarg("dependencies"))
                if child_ref is None or child_ref.kind != "ref":
                    continue
                child = self.route_object(mod, call.scope, child_ref.parts)
                if child is None or (verb == "mount") != child.is_root:
                    continue
                self.mounts.setdefault(child.var, []).append(_Mount(parent, prefix, deps))

    def parameter_dependencies(self, mod: PyModule, fn) -> tuple[Value, ...]:
        """Depends(...) reached through a parameter's annotation or default
        naming an alias, e.g. `user: CurrentUser` with
        `CurrentUser = Annotated[User, Depends(get_current_user)]`."""
        found: list[Value] = []
        for ref in fn.parameter_refs:
            sym = self.resolver.resolve_ref(mod, fn.outer, ref.parts).sym
            if isinstance(sym, VarSym):
                scope = self.resolver.modules[sym.path].scopes[sym.scope_key]
                found.extend(scope.dependency_aliases.get(sym.name, ()))
        return tuple(found)

    def chains(self, obj: RouteObject, seen: frozenset[VarSym] = frozenset()) -> list[_Chain]:
        own_deps = _items(obj.ctor.kwarg("dependencies"))
        mounts = [m for m in self.mounts.get(obj.var, []) + self._ctor_mounts(obj)
                  if m.parent.var not in seen and m.parent.var != obj.var]
        if obj.is_root:
            out = [_Chain("", own_deps, True)] if not mounts else []
            for mount in mounts:                      # an app mounted in another app
                path, ok = _literal(mount.prefix)
                for parent in self.chains(mount.parent, seen | {obj.var}):
                    out.append(_Chain(parent.prefix + path.rstrip("/"), own_deps, parent.resolved and ok))
            return out or [_Chain("", own_deps, False)]
        own_prefix, own_ok = _literal(obj.own_prefix())
        out = []
        for mount in mounts:
            inc_prefix, inc_ok = _literal(mount.prefix)
            for parent in self.chains(mount.parent, seen | {obj.var}):
                if obj.framework == "flask":
                    # register_blueprint(url_prefix=...) replaces the blueprint's own.
                    if mount.prefix is not None:
                        prefix, ok = flask_join(parent.prefix, inc_prefix), inc_ok
                    else:
                        prefix, ok = flask_join(parent.prefix, own_prefix), own_ok
                else:
                    prefix, ok = parent.prefix + inc_prefix + own_prefix, inc_ok and own_ok
                deps = parent.dependencies + mount.dependencies + own_deps
                out.append(_Chain(prefix, deps, parent.resolved and ok))
        return out or [_Chain(own_prefix, own_deps, False)]

    def _ctor_mounts(self, obj: RouteObject) -> list[_Mount]:
        """Api(app) / Api(blueprint): the app it was built with."""
        if obj.kind != "api":
            return []
        mod = self.resolver.modules[obj.var.path]
        target = obj.ctor.args[0] if obj.ctor.args else obj.ctor.kwarg("app")
        parent = self._flask_parent(mod, mod.scopes[obj.var.scope_key], target)
        return [_Mount(parent, None, ())] if parent is not None else []

    def resources(self) -> list[tuple[RouteObject, ClassSym, tuple[Value, ...], Value]]:
        """(api or namespace, resource class, URL values, registering call or decorator)."""
        found = []
        for mod in self.modules:
            for call in mod.calls:                    # api.add_resource(Cls, "/a", "/b")
                c = call.call
                if c.parts[-1] != "add_resource" or len(c.parts) < 2 or not c.args:
                    continue
                obj = self.route_object(mod, call.scope, c.parts[:-1])
                cls = self.resolver.resolve_ref(mod, call.scope, c.args[0].parts).sym \
                    if c.args[0].kind == "ref" else None
                urls = c.args[1:] or _items(c.kwarg("urls"))
                if obj is not None and obj.resources and isinstance(cls, ClassSym):
                    found.append((obj, cls, urls, c))
            for pc in mod.classes.values():           # @api.route("/a") / @ns.route("/a") on the class
                for dec in pc.decorators:
                    if dec.kind != "call" or dec.parts[-1] != "route" or len(dec.parts) < 2:
                        continue
                    obj = self.route_object(mod, pc.outer, dec.parts[:-1])
                    if obj is not None and obj.resources:
                        found.append((obj, ClassSym(mod.path, pc.qualname), dec.args, dec))
        return found

    def resource_evidence(self, cls: ClassSym) -> list[str]:
        """Auth-named entries of `method_decorators` / `decorators` on the class
        or a project base class, and auth-named class decorators."""
        found = []
        for c in self.resolver.mro(cls):
            pc = self.resolver.modules[c.path].classes[c.qualname]
            found += _decorator_evidence(pc.decorators, None)
            for name in _RESOURCE_DECORATOR_LISTS:
                for value in pc.scope.assigns.get(name, []):
                    found += _decorator_evidence(_items(value), None)
        return found

    def detect(self) -> list[EndpointDef]:
        self.collect_mounts()
        endpoints: dict[str, EndpointDef] = {}
        for obj, cls, urls, site in self.resources():
            class_evidence = self.resource_evidence(cls)
            for verb in _RESOURCE_VERBS:
                member = self.resolver.class_member(cls, verb)
                fn = self.functions.get(member.id) if isinstance(member, FuncSym) else None
                if fn is None:
                    continue
                evidence = class_evidence + _decorator_evidence(fn.decorators, None) + self.body_evidence(fn)
                for url in urls:
                    route, route_ok = _literal(url)
                    for chain in self.chains(obj):
                        self._add(endpoints, obj, verb.upper(), flask_join(chain.prefix, route), fn,
                                  site.line, evidence, chain.resolved and route_ok)
        for mod in self.modules:
            for fn in mod.functions:
                for dec in fn.decorators:
                    if dec.kind != "call" or len(dec.parts) < 2:
                        continue
                    obj = self.route_object(mod, fn.outer, dec.parts[:-1])
                    if obj is None or obj.resources:
                        continue
                    methods = _methods(obj.framework, dec)
                    if not methods:
                        continue
                    route_value = dec.args[0] if dec.args else dec.kwarg(
                        "rule" if obj.framework == "flask" else "path")
                    route, route_ok = _literal(route_value)
                    evidence = _decorator_evidence(fn.decorators, dec) + self.body_evidence(fn)
                    handler_deps = fn.dependencies + self.parameter_dependencies(mod, fn)
                    for chain in self.chains(obj):
                        deps = chain.dependencies + _items(dec.kwarg("dependencies")) + handler_deps
                        found = evidence + _dependency_evidence(deps)
                        if obj.framework == "flask":
                            path = flask_join(chain.prefix, route)
                        else:
                            path = chain.prefix + route
                        for method in methods:
                            self._add(endpoints, obj, method, path, fn, dec.line, found,
                                      chain.resolved and route_ok)
        return list(endpoints.values())

    @staticmethod
    def _add(endpoints: dict[str, EndpointDef], obj: RouteObject, method: str, path: str,
             fn: PyFunction, line: int, evidence: list[str], resolved: bool) -> None:
        eid = endpoint_id(method, path, fn.record.id)
        endpoints.setdefault(eid, EndpointDef(
            id=eid,
            framework=obj.framework,
            method=method,
            path=path,
            handler_id=fn.record.id,
            file=fn.record.file,
            line=line,
            auth_required=bool(evidence),
            auth_evidence=tuple(dict.fromkeys(evidence)),
            prefix_resolved=resolved,
        ))


def _methods(framework: str, dec: Value) -> list[str]:
    verb = dec.parts[-1]
    if framework == "fastapi":
        if verb in _FASTAPI_VERBS:
            return [verb.upper()]
        if verb == "websocket":
            return ["WEBSOCKET"]
        if verb != "api_route":
            return []
    else:
        if verb in _FLASK_VERBS:
            return [verb.upper()]
        if verb != "route":
            return []
    listed = dec.kwarg("methods")
    if listed is None:
        return ["GET"]
    if listed.kind != "list" or any(i.kind != "str" for i in listed.items):
        return ["*"]
    return list(dict.fromkeys((i.string or "").upper() for i in listed.items))


def _dependency_evidence(deps: tuple[Value, ...]) -> list[str]:
    found = []
    for dep in deps:
        if dep.kind != "call" or dep.parts[-1] not in ("Depends", "Security"):
            continue
        target = dep.args[0] if dep.args else dep.kwarg("dependency")
        name = ".".join(target.parts) if target is not None and target.kind in ("ref", "call") else ""
        if dep.parts[-1] == "Security" or AUTH_NAME.search(name.split(".")[-1]):
            found.append(f"{dep.parts[-1]}({name})")
    return found


def _decorator_evidence(decorators: tuple[Value, ...], route: Value) -> list[str]:
    found = []
    for dec in decorators:
        if dec is route or dec.kind not in ("ref", "call"):
            continue
        if AUTH_NAME.search(dec.parts[-1]):
            found.append("@" + ".".join(dec.parts) + ("()" if dec.kind == "call" else ""))
    return found


def detect_routes(modules: list[PyModule], resolver: Resolver) -> list[EndpointDef]:
    return _Detector(modules, resolver).detect()
