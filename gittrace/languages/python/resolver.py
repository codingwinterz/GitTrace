"""
gittrace.languages.python.resolver — resolve names and calls across a project.

Best effort and deliberately conservative: a call resolves to a project
function only through a chain of exact bindings, never by bare name or
substring. What it follows:

  - Python's scoping: enclosing function scopes, then the module; class bodies
    are skipped by the code inside their methods; a name bound anywhere in a
    function (parameter, assignment, loop variable, ...) is local there.
  - nested functions (`outer.inner`), same-file functions and classes;
  - `import x`, `import x as z`, `from x import y [as z]`, relative imports,
    re-exports (`from .db import Repo` in a package __init__) and star imports;
  - `self.method()` / `cls.method()` / `super().method()`, through project base
    classes (left-to-right, depth-first);
  - a local or module variable assigned exactly once from a project class
    (`repo = Repo(); repo.get()`), and `Class()` itself, which runs __init__;
  - `getattr(obj, "name")(...)` (dynamic dispatch): with a literal name it is
    resolved exactly as `obj.name()` would be; with a computed name every
    member the receiver is known to hold becomes a low-confidence (dynamic)
    edge, and an unknown receiver leaves an unresolved `dynamic` marker.

Everything else is reported unresolved with the best full name available
(aliases expanded) — those are the sink candidates for Phase 4.
"""

from __future__ import annotations

import builtins
from dataclasses import dataclass

from gittrace.languages.base import CallSite
from gittrace.languages.python.parser import PyClass, PyModule, RawCall, Scope, Value

BUILTINS = frozenset(dir(builtins))
_MAX_DEPTH = 25
# A computed-name getattr dispatch fans out to the receiver's members. Beyond
# this many candidates the set says nothing useful; the site stays a marker.
_MAX_DYNAMIC_CANDIDATES = 25
_MARKER_TEXT = 60


# -- symbols ------------------------------------------------------------------

@dataclass(frozen=True)
class ModSym:
    path: str


@dataclass(frozen=True)
class FuncSym:
    id: str


@dataclass(frozen=True)
class ClassSym:
    path: str
    qualname: str


@dataclass(frozen=True)
class InstSym:
    """An instance of a project class (`self`, or `x = Cls()`)."""
    cls: ClassSym


@dataclass(frozen=True)
class SuperSym:
    cls: ClassSym


@dataclass(frozen=True)
class VarSym:
    path: str
    scope_key: str
    name: str


@dataclass(frozen=True)
class ExtSym:
    """A name outside the project, e.g. `subprocess.run` or the builtin `eval`."""
    dotted: str
    origin: str          # builtin | import


@dataclass(frozen=True)
class ExtInst:
    """An instance built by an external callable, e.g. `app = FastAPI()`."""
    dotted: str


@dataclass(frozen=True)
class ImportRef:
    target: str
    from_path: str


class _Local:
    """A name bound locally in a way the resolver does not track."""


LOCAL = _Local()


@dataclass(frozen=True)
class Resolution:
    sym: object | None
    name: str            # best full dotted name
    origin: str          # builtin | import | project | unknown


def _root_origin(sym: object | None) -> str:
    if isinstance(sym, ExtSym):
        return sym.origin
    if isinstance(sym, (ModSym, ClassSym, FuncSym)):
        return "project"
    return "unknown"


# Constructors whose `target=` runs in another thread (a call edge to it).
THREAD_CTORS = frozenset({"threading.Thread"})


class Resolver:
    def __init__(self, modules: list[PyModule]):
        self.modules = {m.path: m for m in modules}
        package_dirs = {m.path.rpartition("/")[0] for m in modules if m.is_package}
        self.index: dict[str, list[str]] = {}
        for m in modules:
            for name in _module_names(m, package_dirs):
                self.index.setdefault(name, []).append(m.path)
        self._mro_cache: dict[ClassSym, list[ClassSym]] = {}
        self._deref_cache: dict[VarSym, object | None] = {}

    # -- modules -------------------------------------------------------------

    def lookup_module(self, name: str, from_path: str) -> str | None:
        """A dotted module name -> the file defining it. When several files
        claim the name, prefer the one nearest the importing file; give up on
        a tie rather than guess."""
        candidates = self.index.get(name)
        if not candidates:
            return None
        if len(candidates) == 1:
            return candidates[0]
        here = from_path.split("/")[:-1]

        def shared(path: str) -> int:
            n = 0
            for a, b in zip(here, path.split("/")[:-1]):
                if a != b:
                    break
                n += 1
            return n

        ranked = sorted(candidates, key=shared, reverse=True)
        if shared(ranked[0]) == shared(ranked[1]):
            return None
        return ranked[0]

    # -- names ---------------------------------------------------------------

    def _scope_lookup(self, mod: PyModule, scope: Scope, name: str, depth: int = 0):
        """The binding of `name` in exactly this scope, or None if unbound here."""
        if name in scope.globals:
            return None
        if name in scope.imports:
            return ImportRef(scope.imports[name], mod.path)
        if name in scope.defs:
            return FuncSym(scope.defs[name])
        if name in scope.classes:
            return ClassSym(mod.path, scope.classes[name])
        if name in scope.assigns:
            return VarSym(mod.path, scope.key, name)
        if scope.kind == "function" and name in scope.locals:
            return LOCAL
        if scope.kind == "module" and depth < _MAX_DEPTH:
            for star in scope.stars:
                target = self.lookup_module(star, mod.path)
                if target is not None and target != mod.path:
                    found = self._member(ModSym(target), name, depth + 1)
                    if found is not None:
                        return found
        return None

    def _lookup(self, mod: PyModule, scope: Scope, name: str):
        s: Scope | None = scope
        first = True
        while s is not None:
            if first or s.kind != "class":
                found = self._scope_lookup(mod, s, name)
                if found is not None:
                    return found
            first = False
            s = s.parent
        return None

    def _receiver(self, mod: PyModule, scope: Scope, name: str):
        """`self`/`cls` of the nearest enclosing method, if `name` is it."""
        s: Scope | None = scope
        while s is not None:
            if s.kind == "function" and s.self_class is not None:
                if name != s.self_name:
                    return None
                cls = ClassSym(mod.path, s.self_class)
                return cls if s.is_classmethod else InstSym(cls)
            s = s.parent
        return None

    def _enclosing_class(self, mod: PyModule, scope: Scope) -> ClassSym | None:
        s: Scope | None = scope
        while s is not None:
            if s.kind == "function" and s.self_class is not None:
                return ClassSym(mod.path, s.self_class)
            s = s.parent
        return None

    def resolve_ref(self, mod: PyModule, scope: Scope, parts: tuple[str, ...], depth: int = 0) -> Resolution:
        root, rest = parts[0], parts[1:]
        if root == "super()":
            cls = self._enclosing_class(mod, scope)
            return self._walk(SuperSym(cls) if cls else None, rest, root, "unknown", depth)
        inner = root[:-2].split(".") if root.endswith("()") else []
        if inner and all(p.isidentifier() for p in inner) and depth < _MAX_DEPTH:
            # `Repo().get_user()`: a method on a fresh instance of a project class.
            made = self.resolve_ref(mod, scope, tuple(inner), depth + 1).sym
            if isinstance(made, ClassSym):
                return self._walk(InstSym(made), rest, root, "unknown", depth)
        if not root.isidentifier():
            return Resolution(None, ".".join(parts), "unknown")

        sym = self._receiver(mod, scope, root)
        if sym is None:
            sym = self._lookup(mod, scope, root)
            if isinstance(sym, ImportRef):
                return self._resolve_absolute(".".join((sym.target,) + rest), sym.from_path, depth)
            if sym is None and root in BUILTINS:
                sym = ExtSym(root, "builtin")
            elif sym is LOCAL:
                sym = None
        return self._walk(sym, rest, root, _root_origin(sym), depth)

    def _resolve_absolute(self, dotted: str, from_path: str, depth: int = 0) -> Resolution:
        """An absolute dotted name -> the longest prefix that is a project
        module, then attribute access for the rest; otherwise external."""
        parts = dotted.split(".")
        for i in range(len(parts), 0, -1):
            target = self.lookup_module(".".join(parts[:i]), from_path)
            if target is not None:
                if depth >= _MAX_DEPTH:            # an import cycle
                    return Resolution(None, dotted, "project")
                return self._walk(ModSym(target), tuple(parts[i:]), ".".join(parts[:i]),
                                  "project", depth + 1)
        return Resolution(ExtSym(dotted, "import"), dotted, "import")

    def _walk(self, sym, rest: tuple[str, ...], name: str, origin: str, depth: int) -> Resolution:
        for k, attr in enumerate(rest):
            nxt = self._member(sym, attr, depth) if sym is not None else None
            if isinstance(nxt, ImportRef):
                remaining = (nxt.target,) + rest[k + 1:]
                return self._resolve_absolute(".".join(remaining), nxt.from_path, depth + 1)
            name = f"{name}.{attr}"
            sym = nxt
        return Resolution(sym, name, origin)

    def _member(self, sym, attr: str, depth: int = 0):
        if depth > _MAX_DEPTH:
            return None
        if isinstance(sym, ExtSym):
            return ExtSym(f"{sym.dotted}.{attr}", sym.origin)
        if isinstance(sym, ModSym):
            mod = self.modules[sym.path]
            found = self._scope_lookup(mod, mod.scope, attr, depth + 1)
            if found is not None and found is not LOCAL:
                return found
            sub = self.lookup_module(f"{mod.name}.{attr}" if mod.name else attr, sym.path)
            return ModSym(sub) if sub is not None else None
        if isinstance(sym, ClassSym):
            return self.class_member(sym, attr)
        if isinstance(sym, InstSym):
            found = self.class_member(sym.cls, attr)
            return found if isinstance(found, FuncSym) else None
        if isinstance(sym, SuperSym):
            for base in self.mro(sym.cls)[1:]:
                found = self.class_member(base, attr, mro=False)
                if isinstance(found, FuncSym):
                    return found
            return None
        if isinstance(sym, VarSym):
            value = self.deref(sym, depth + 1)
            if isinstance(value, (InstSym, ClassSym, ModSym, VarSym)):
                return self._member(value, attr, depth + 1)
            return None
        return None

    # -- classes -------------------------------------------------------------

    def _class(self, cls: ClassSym) -> PyClass | None:
        mod = self.modules.get(cls.path)
        return mod.classes.get(cls.qualname) if mod else None

    def mro(self, cls: ClassSym) -> list[ClassSym]:
        """Project classes in lookup order: the class, then its project bases
        depth-first, left to right. External bases are not followed."""
        if cls in self._mro_cache:
            return self._mro_cache[cls]
        order: list[ClassSym] = []
        self._mro_cache[cls] = order          # cycle guard while computing
        stack = [cls]
        seen = set()
        while stack:
            c = stack.pop()
            if c in seen:
                continue
            seen.add(c)
            pc = self._class(c)
            if pc is None:
                continue
            order.append(c)
            mod = self.modules[c.path]
            bases = []
            for base in pc.bases:
                r = self.resolve_ref(mod, pc.outer, base.parts)
                if isinstance(r.sym, ClassSym):
                    bases.append(r.sym)
            stack.extend(reversed(bases))
        return order

    def class_member(self, cls: ClassSym, attr: str, mro: bool = True):
        for c in (self.mro(cls) if mro else [cls]):
            pc = self._class(c)
            if pc is None:
                continue
            if attr in pc.scope.defs:
                return FuncSym(pc.scope.defs[attr])
            if attr in pc.scope.classes:
                return ClassSym(c.path, pc.scope.classes[attr])
        return None

    # -- variables -----------------------------------------------------------

    def assignment(self, var: VarSym) -> Value | None:
        """The value a variable is bound to, if it is bound exactly one way."""
        mod = self.modules[var.path]
        values = mod.scopes[var.scope_key].assigns.get(var.name, [])
        if not values or len({v.text for v in values}) != 1:
            return None
        return values[0]

    def deref(self, var: VarSym, depth: int = 0):
        """What a variable holds: InstSym for `Cls()`, ExtInst for an external
        constructor, the target symbol for an alias (`r = users.router`)."""
        if var in self._deref_cache:
            return self._deref_cache[var]
        self._deref_cache[var] = None          # cycle guard
        result = None
        value = self.assignment(var)
        if value is not None and depth < _MAX_DEPTH and value.kind in ("call", "ref"):
            mod = self.modules[var.path]
            r = self.resolve_ref(mod, mod.scopes[var.scope_key], value.parts, depth + 1)
            if value.kind == "ref":
                result = r.sym
            elif isinstance(r.sym, ClassSym):
                result = InstSym(r.sym)
            elif isinstance(r.sym, ExtSym):
                result = ExtInst(r.sym.dotted)
        self._deref_cache[var] = result
        return result

    # -- calls ---------------------------------------------------------------

    def resolve_call(self, mod: PyModule, call: RawCall) -> list[CallSite]:
        """Every CallSite for one parsed call: one normally, one per candidate
        target for a getattr dispatch whose name is computed at run time."""
        if call.dispatch is not None:
            return self._dispatch(mod, call)
        dotted, origin, callee_id = self._target(mod, call)
        sites = [CallSite(call.caller_id, call.call.line, dotted, origin, callee_id,
                          site=call.site, args=call.args, kwargs=call.kwargs)]
        if dotted in THREAD_CTORS:
            sites += self._thread_target(mod, call)
        return sites

    def _thread_target(self, mod: PyModule, call: RawCall) -> list[CallSite]:
        """`threading.Thread(target=f)`: the thread runs `f`, so the function
        that builds the thread gets a (dynamic) edge to it. Whether `.start()`
        is called is not checked."""
        c = call.call
        target = c.kwarg("target") or (c.args[1] if len(c.args) > 1 else None)
        if target is None or target.kind != "ref":
            return []
        ref = RawCall(call.caller_id, call.scope, Value("ref", target.text, c.line, parts=target.parts))
        dotted, origin, callee_id = self._target(mod, ref)
        if callee_id is None:
            return []
        return [CallSite(call.caller_id, c.line, dotted, origin, callee_id, site=call.site, dynamic=True)]

    # -- getattr dispatch -----------------------------------------------------

    def _dispatch(self, mod: PyModule, call: RawCall) -> list[CallSite]:
        """`getattr(receiver, name)(...)` — dynamic dispatch.

        A string-literal name resolves exactly as `receiver.name()` would.
        A name computed at run time has no single target, so it is not
        dropped: every function the receiver is known to hold becomes a
        low-confidence (dynamic) edge, and a receiver whose contents are
        unknown leaves a documented unresolved `dynamic` marker instead of
        nothing at all.
        """
        args = call.dispatch.args if call.dispatch is not None else ()
        receiver = args[0] if len(args) > 0 else None
        name = args[1] if len(args) > 1 else None
        literal = name is not None and name.kind == "str" and bool(name.string)
        if (literal and name is not None and receiver is not None and receiver.kind == "ref"
                and name.string.isidentifier()):
            dotted, origin, callee_id = self._target(mod, self._as_attribute(receiver, name.string, call))
            return [CallSite(call.caller_id, call.call.line, dotted, origin, callee_id,
                             site=call.site, args=call.args, kwargs=call.kwargs, dynamic=True)]
        if not literal:                       # a computed name: the target set may be knowable
            candidates = self._dispatch_candidates(mod, call, receiver)
            if candidates:
                return candidates
        # No target to point at: an unknown receiver, or a literal name no
        # function can carry. Keep the dispatch as a documented marker.
        dotted = f"getattr({_expression(receiver)}, {_expression(name)})"
        return [CallSite(call.caller_id, call.call.line, dotted, "dynamic", None,
                         site=call.site, args=call.args, kwargs=call.kwargs, dynamic=True)]

    def _as_attribute(self, receiver: Value, attr: str, call: RawCall) -> RawCall:
        """The same call written `receiver.attr(...)`: one synthesized reference."""
        return RawCall(call.caller_id, call.scope,
                       Value("ref", receiver.text, call.call.line,
                             parts=receiver.parts + (attr,)))

    def _dispatch_candidates(self, mod: PyModule, call: RawCall,
                             receiver: Value | None) -> list[CallSite]:
        """The functions `getattr(receiver, <computed>)()` could call: every
        member of the class, instance or module `receiver` resolves to, when
        that is a bounded set (one low-confidence CallSite per member)."""
        if receiver is None or receiver.kind != "ref":
            return []
        sym = self.resolve_ref(mod, call.scope, receiver.parts).sym
        if isinstance(sym, VarSym):
            sym = self.deref(sym)
        members: list[str] = []
        if isinstance(sym, ModSym):
            target = self.modules.get(sym.path)
            members = sorted(n for n in (target.scope.defs if target is not None else ())
                             if not n.startswith("__"))
        elif isinstance(sym, (ClassSym, InstSym)):
            for cls in (self.mro(sym.cls) if isinstance(sym, InstSym) else self.mro(sym)):
                target = self._class(cls)
                if target is not None:
                    members.extend(n for n in sorted(target.scope.defs)
                                   if not n.startswith("__") and n not in members)
        if not members or len(members) > _MAX_DYNAMIC_CANDIDATES:
            return []
        out: list[CallSite] = []
        for member in members:
            dotted, origin, callee_id = self._target(mod, self._as_attribute(receiver, member, call))
            if callee_id is not None:
                out.append(CallSite(call.caller_id, call.call.line, dotted, origin, callee_id,
                                    site=call.site, args=call.args, kwargs=call.kwargs, dynamic=True))
        return out

    def _target(self, mod: PyModule, call: RawCall) -> tuple[str, str, str | None]:
        """(dotted name, origin, project function id or None) for a call."""
        r = self.resolve_ref(mod, call.scope, call.call.parts)
        sym = r.sym
        if isinstance(sym, VarSym):
            sym = self.deref(sym)
        if isinstance(sym, FuncSym):
            return r.name, "project", sym.id
        if isinstance(sym, ClassSym):
            init = self.class_member(sym, "__init__")
            if isinstance(init, FuncSym):
                return r.name, "project", init.id
            return r.name, "class", None
        if isinstance(sym, InstSym):
            dunder = self.class_member(sym.cls, "__call__")
            if isinstance(dunder, FuncSym):
                return r.name, "project", dunder.id
        if isinstance(sym, ExtSym) and sym is not r.sym:      # run = subprocess.run; run()
            return sym.dotted, sym.origin, None
        return r.name, r.origin, None


def _expression(value: Value | None) -> str:
    """A short single-line rendering of one argument, for a marker's name."""
    if value is None:
        return "..."
    text = " ".join(value.text.split())[:_MARKER_TEXT]
    return text or "..."


def _module_names(mod: PyModule, package_dirs: set[str]) -> list[str]:
    """The dotted names a file can be imported by:
      - its path from the project root (`src.dispatch.case_cost.service`);
      - its path from the parent of the topmost package directory above it,
        with directories lacking __init__.py below that treated as namespace
        packages (`dispatch.case_cost.service`; `backend/app/db.py` is
        `app.db` when `app/` has an __init__.py);
      - its bare name when its own directory is not a package, as for a
        script importing a sibling (`tools/util.py` is `util`).
    Clashing names are disambiguated, or left unresolved, by lookup_module."""
    parts = mod.name.split(".") if mod.name else []
    dirs = mod.path.split("/")[:-1]
    names = [mod.name] if mod.name else []
    top = next((k for k in range(1, len(dirs) + 1) if "/".join(dirs[:k]) in package_dirs), None)
    starts = [top - 1] if top is not None else []
    if not mod.is_package and "/".join(dirs) not in package_dirs:
        starts.append(len(dirs))
    for j in starts:
        name = ".".join(parts[j:])
        if name and name not in names:
            names.append(name)
    return names
