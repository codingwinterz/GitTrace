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

auth_required is true only on obvious evidence: a FastAPI dependency
(route, router, include_router or app level, or in the handler's parameters,
directly or through an alias such as
`CurrentUser = Annotated[User, Depends(get_current_user)]`) whose target is
named like auth, any `Security(...)`, or a handler decorator named like auth
(`@login_required`, `@jwt_required()`, ...). Default false.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from gittrace.languages.base import EndpointDef, endpoint_id
from gittrace.languages.python.parser import PyModule, Value
from gittrace.languages.python.resolver import ExtInst, Resolver, VarSym

FASTAPI_APPS = frozenset({"fastapi.FastAPI", "fastapi.applications.FastAPI"})
FASTAPI_ROUTERS = frozenset({"fastapi.APIRouter", "fastapi.routing.APIRouter"})
FLASK_APPS = frozenset({"flask.Flask", "flask.app.Flask"})
FLASK_BLUEPRINTS = frozenset({"flask.Blueprint", "flask.blueprints.Blueprint"})

_FASTAPI_VERBS = frozenset({"get", "post", "put", "delete", "patch", "options", "head", "trace"})
_FLASK_VERBS = frozenset({"get", "post", "put", "delete", "patch"})

AUTH_NAME = re.compile(
    r"auth|current_user|current_active_user|logged_in|login|token|jwt|oauth|bearer"
    r"|api_?key|permission|require|admin|verify",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class RouteObject:
    var: VarSym
    framework: str        # fastapi | flask
    is_root: bool         # an app, not a router/blueprint
    ctor: Value


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

    def route_object(self, mod: PyModule, scope, parts: tuple[str, ...]) -> RouteObject | None:
        sym = self.resolver.resolve_ref(mod, scope, parts).sym
        if not isinstance(sym, VarSym):
            return None
        held = self.resolver.deref(sym)
        ctor = self.resolver.assignment(sym)
        if not isinstance(held, ExtInst) or ctor is None:
            return None
        if held.dotted in FASTAPI_APPS:
            return RouteObject(sym, "fastapi", True, ctor)
        if held.dotted in FASTAPI_ROUTERS:
            return RouteObject(sym, "fastapi", False, ctor)
        if held.dotted in FLASK_APPS:
            return RouteObject(sym, "flask", True, ctor)
        if held.dotted in FLASK_BLUEPRINTS:
            return RouteObject(sym, "flask", False, ctor)
        return None

    def collect_mounts(self) -> None:
        for mod in self.modules:
            for call in mod.calls:
                parts = call.call.parts
                verb = parts[-1]
                if len(parts) < 2 or verb not in ("include_router", "register_blueprint", "mount"):
                    continue
                parent = self.route_object(mod, call.scope, parts[:-1])
                if parent is None:
                    continue
                c = call.call
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
        mounts = [m for m in self.mounts.get(obj.var, [])
                  if m.parent.var not in seen and m.parent.var != obj.var]
        if obj.is_root:
            out = [_Chain("", own_deps, True)] if not mounts else []
            for mount in mounts:                      # an app mounted in another app
                path, ok = _literal(mount.prefix)
                for parent in self.chains(mount.parent, seen | {obj.var}):
                    out.append(_Chain(parent.prefix + path.rstrip("/"), own_deps, parent.resolved and ok))
            return out or [_Chain("", own_deps, False)]
        own_value = obj.ctor.kwarg("url_prefix" if obj.framework == "flask" else "prefix")
        own_prefix, own_ok = _literal(own_value)
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

    def detect(self) -> list[EndpointDef]:
        self.collect_mounts()
        endpoints: dict[str, EndpointDef] = {}
        for mod in self.modules:
            for fn in mod.functions:
                for dec in fn.decorators:
                    if dec.kind != "call" or len(dec.parts) < 2:
                        continue
                    obj = self.route_object(mod, fn.outer, dec.parts[:-1])
                    if obj is None:
                        continue
                    methods = _methods(obj.framework, dec)
                    if not methods:
                        continue
                    route_value = dec.args[0] if dec.args else dec.kwarg(
                        "rule" if obj.framework == "flask" else "path")
                    route, route_ok = _literal(route_value)
                    evidence = _decorator_evidence(fn.decorators, dec)
                    handler_deps = fn.dependencies + self.parameter_dependencies(mod, fn)
                    for chain in self.chains(obj):
                        deps = chain.dependencies + _items(dec.kwarg("dependencies")) + handler_deps
                        found = evidence + _dependency_evidence(deps)
                        if obj.framework == "flask":
                            path = flask_join(chain.prefix, route)
                        else:
                            path = chain.prefix + route
                        for method in methods:
                            eid = endpoint_id(method, path, fn.record.id)
                            endpoints.setdefault(eid, EndpointDef(
                                id=eid,
                                framework=obj.framework,
                                method=method,
                                path=path,
                                handler_id=fn.record.id,
                                file=fn.record.file,
                                line=dec.line,
                                auth_required=bool(found),
                                auth_evidence=tuple(dict.fromkeys(found)),
                                prefix_resolved=chain.resolved and route_ok,
                            ))
        return list(endpoints.values())


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
