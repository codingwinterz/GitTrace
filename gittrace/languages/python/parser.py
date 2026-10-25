"""
gittrace.languages.python.parser — one Python file -> a PyModule, with tree-sitter.

The parser records facts and resolves nothing across files:
  - every function, method and nested function, with its stable ID, span and
    source;
  - one Scope per module, class and function, holding the names bound there
    (defs, classes, imports with relative imports made absolute, simple
    assignments, other locals) so the resolver can apply Python's scoping;
  - every call expression, attributed to the scope it runs in. Decorators,
    default arguments, annotations and class bodies run in the enclosing
    scope, so their calls belong to the enclosing function, or to the
    `<module>` pseudo-function at import time;
  - for the rules: where each call is (line, column, source lines) and what
    each argument is (ArgFact: constant, built string, parameter, other, and
    which parameters it derives from), plus every string constant bound to a
    name (AssignFact). This runs once the whole file has been walked, so a
    variable's assignments are all known when a call using it is classified.

Only the expression traversal inside a scope is iterative; recursion happens
per def/class, so a deeply nested expression cannot hit the recursion limit.
"""

from __future__ import annotations

import codecs
import hashlib
from dataclasses import dataclass, field

import tree_sitter_python
from tree_sitter import Language, Node, Parser

from gittrace.languages.base import (
    MODULE_SCOPE,
    ArgFact,
    AssignFact,
    FileRecord,
    FunctionDef,
    SiteFacts,
    function_id,
)

PY_LANGUAGE = Language(tree_sitter_python.language())

# Calls whose arguments the route detector needs. Other calls keep only the
# callee name, so large literal arguments are not copied for nothing.
_KEEP_ARGS = frozenset({"include_router", "register_blueprint", "mount"})
_DEPENDENCY_CALLS = frozenset({"Depends", "Security"})
_TEXT_LIMIT = 200
_SNIPPET_LINES = 20
_MAX_DEPTH = 50
_LITERAL_TYPES = frozenset({"integer", "float", "true", "false", "none"})
_PATTERN_TYPES = ("pattern_list", "tuple_pattern", "list_pattern", "tuple", "list",
                  "parenthesized_expression", "list_splat_pattern", "as_pattern_target")


class ParseError(Exception):
    """The file has a syntax error tree-sitter could only recover from."""


@dataclass(frozen=True)
class Value:
    """A small, resolver-friendly picture of an expression.

    kind: str (string literal) | list (list/tuple display) | ref (a dotted
    name) | call | other. `parts` is the dotted name for a ref, or the callee
    for a call; its first element can be a non-name root such as `super()`,
    `get_db()` or `<string>`.
    """

    kind: str
    text: str
    line: int
    string: str | None = None
    parts: tuple[str, ...] = ()
    items: tuple["Value", ...] = ()
    args: tuple["Value", ...] = ()
    kwargs: tuple[tuple[str, "Value"], ...] = ()

    def kwarg(self, name: str) -> "Value | None":
        for key, value in self.kwargs:
            if key == name:
                return value
        return None


@dataclass(eq=False)
class Scope:
    kind: str                         # module | class | function
    key: str                          # qualified name; "" for the module
    parent: "Scope | None"
    func_id: str | None = None        # set on function scopes
    defs: dict[str, str] = field(default_factory=dict)       # name -> function id (last def wins)
    classes: dict[str, str] = field(default_factory=dict)    # name -> class qualname
    imports: dict[str, str] = field(default_factory=dict)    # name -> absolute dotted target
    stars: list[str] = field(default_factory=list)           # `from x import *` targets
    assigns: dict[str, list[Value]] = field(default_factory=dict)
    # Names bound to something holding Depends(...)/Security(...), e.g.
    # `CurrentUser = Annotated[User, Depends(get_current_user)]`.
    dependency_aliases: dict[str, tuple[Value, ...]] = field(default_factory=dict)
    locals: set[str] = field(default_factory=set)
    globals: set[str] = field(default_factory=set)
    params: tuple[str, ...] = ()          # function scopes: parameter names, in order
    # Methods only: the first parameter (self/cls) and the owning class.
    self_name: str | None = None
    self_class: str | None = None
    is_classmethod: bool = False


@dataclass(eq=False)
class PyFunction:
    record: FunctionDef
    scope: Scope                      # the function body
    outer: Scope                      # where it is defined; decorators run here
    decorators: tuple[Value, ...]
    dependencies: tuple[Value, ...]   # Depends(...)/Security(...) calls in its parameters
    parameter_refs: tuple[Value, ...] = ()   # names used as a parameter's annotation or default


@dataclass(eq=False)
class PyClass:
    qualname: str
    scope: Scope
    outer: Scope
    bases: tuple[Value, ...]


@dataclass(eq=False)
class RawCall:
    caller_id: str
    scope: Scope
    call: Value
    site: SiteFacts | None = None
    args: tuple[ArgFact, ...] = ()
    kwargs: tuple[tuple[str, ArgFact], ...] = ()


@dataclass(eq=False)
class PyModule:
    path: str
    name: str                         # dotted module name from the project root
    is_package: bool
    record: FileRecord
    scope: Scope
    scopes: dict[str, Scope]
    functions: list[PyFunction]
    classes: dict[str, PyClass]
    calls: list[RawCall]
    module_function: FunctionDef | None    # the <module> node, if the file calls at import time
    assignments: list[AssignFact] = field(default_factory=list)
    module_scope: FunctionDef | None = None   # the <module> record, always (a finding may need it)


def module_name(path: str) -> str:
    parts = path[: -len(".py")].split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _text(node: Node | None) -> str:
    if node is None:
        return ""
    return node.text.decode("utf-8", "replace")


def _source(data: bytes) -> str:
    """Stored source text: decoded, with Windows line endings normalised."""
    return data.decode("utf-8", "replace").replace("\r\n", "\n")


def _first_error(root: Node) -> Node | None:
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "ERROR" or node.is_missing:
            return node
        if node.has_error:
            stack.extend(reversed(node.children))
    return None


def parse_module(path: str, data: bytes) -> PyModule:
    """Parse one file. Raises ParseError on a syntax error."""
    if data.startswith(codecs.BOM_UTF8):
        data = data[len(codecs.BOM_UTF8):]
    tree = Parser(PY_LANGUAGE).parse(data)
    if tree.root_node.has_error:
        bad = _first_error(tree.root_node)
        where = f"line {bad.start_point[0] + 1}" if bad is not None else "unknown location"
        raise ParseError(f"syntax error at {where}")
    return _Builder(path, data).build(tree.root_node)


class _Builder:
    def __init__(self, path: str, data: bytes):
        self.path = path
        self.data = data
        self.name = module_name(path)
        self.is_package = path == "__init__.py" or path.endswith("/__init__.py")
        self.module_scope = Scope("module", "", None)
        self.scopes: dict[str, Scope] = {"": self.module_scope}
        self.functions: list[PyFunction] = []
        self.classes: dict[str, PyClass] = {}
        self.calls: list[RawCall] = []
        self.seen: dict[str, int] = {}
        self.module_calls = False
        # Only alive while the tree is: the nodes each fact is computed from.
        # (id(scope), name) -> [(how it was bound, value node)]
        self._flows: dict[tuple[int, str], list[tuple[str, Node]]] = {}
        self._pending_calls: list[tuple[RawCall, Node]] = []
        self._pending_assigns: list[tuple[Scope, str, Node, Node]] = []
        self._line_starts = [0] + [i + 1 for i, b in enumerate(self.data) if b == 0x0A]

    def build(self, root: Node) -> PyModule:
        self._walk(root, self.module_scope)
        assignments = self._complete_facts()
        lines = self.data.count(b"\n") + (0 if self.data.endswith(b"\n") or not self.data else 1)
        record = FileRecord(
            path=self.path,
            language="python",
            sha256=hashlib.sha256(self.data).hexdigest(),
            lines=lines,
        )
        module_scope = FunctionDef(
            id=function_id(self.path, MODULE_SCOPE),
            file=self.path,
            name=MODULE_SCOPE,
            qualified_name=MODULE_SCOPE,
            kind="module",
            start_line=1,
            end_line=max(lines, 1),
            source=_source(self.data),
        )
        return PyModule(
            path=self.path, name=self.name, is_package=self.is_package,
            record=record, scope=self.module_scope, scopes=self.scopes,
            functions=self.functions, classes=self.classes, calls=self.calls,
            module_function=module_scope if self.module_calls else None,
            assignments=assignments, module_scope=module_scope,
        )

    # -- traversal ---------------------------------------------------------

    def _walk(self, node: Node, scope: Scope) -> None:
        stack = [node]
        while stack:
            n = stack.pop()
            t = n.type
            if t == "decorated_definition":
                self._decorated(n, scope)
                continue
            if t == "function_definition":
                self._function(n, scope, n, ())
                continue
            if t == "class_definition":
                self._class(n, scope, n)
                continue
            if t == "import_statement":
                self._import(n, scope)
                continue
            if t == "import_from_statement":
                self._import_from(n, scope)
                continue
            if t == "future_import_statement":
                continue
            if t == "call":
                self._call(n, scope)
            elif t == "assignment":
                self._assignment(n, scope)
            elif t == "augmented_assignment":
                left = n.child_by_field_name("left")
                self._bind(left, scope)
                op = n.child_by_field_name("operator")
                self._flow(scope, left, f"aug{_text(op)}", n.child_by_field_name("right"))
            elif t == "for_statement":
                left = n.child_by_field_name("left")
                self._bind(left, scope)
                self._flow(scope, left, "flow", n.child_by_field_name("right"))
            elif t == "as_pattern_target":
                self._bind(n, scope)
                source = n.parent.named_children[0] if n.parent is not None else None
                if source is not None and source != n:
                    self._flow(scope, n, "flow", source)
            elif t == "named_expression":
                self._bind(n.child_by_field_name("name"), scope)
            elif t in ("global_statement", "nonlocal_statement"):
                scope.globals.update(_text(c) for c in n.named_children if c.type == "identifier")
                continue
            stack.extend(reversed(n.named_children))

    def _bind(self, target: Node | None, scope: Scope) -> None:
        """Record the names a binding target introduces (function scopes only:
        module- and class-level names are looked up through `assigns`)."""
        if target is None or scope.kind != "function":
            return
        stack = [target]
        while stack:
            n = stack.pop()
            if n.type == "identifier":
                scope.locals.add(_text(n))
            elif n.type in ("pattern_list", "tuple_pattern", "list_pattern", "tuple", "list",
                            "parenthesized_expression", "list_splat_pattern", "as_pattern_target"):
                stack.extend(n.named_children)

    # -- definitions -------------------------------------------------------

    def _unique(self, qualname: str) -> str:
        count = self.seen.get(qualname, 0) + 1
        self.seen[qualname] = count
        return qualname if count == 1 else f"{qualname}#{count}"

    def _qualify(self, outer: Scope, name: str) -> str:
        return self._unique(f"{outer.key}.{name}" if outer.key else name)

    def _decorated(self, node: Node, scope: Scope) -> None:
        decorators = []
        for child in node.named_children:
            if child.type != "decorator":
                continue
            self._walk(child, scope)
            expr = child.named_children[0] if child.named_children else None
            if expr is not None:
                decorators.append(self._value(expr, with_args=True))
        definition = node.child_by_field_name("definition")
        if definition is None:
            return
        if definition.type == "function_definition":
            self._function(definition, scope, node, tuple(decorators))
        elif definition.type == "class_definition":
            self._class(definition, scope, node)

    def _function(self, node: Node, outer: Scope, span: Node, decorators: tuple[Value, ...]) -> None:
        name = _text(node.child_by_field_name("name"))
        qualname = self._qualify(outer, name)
        fid = function_id(self.path, qualname)
        kind = {"class": "method", "function": "nested"}.get(outer.kind, "function")
        record = FunctionDef(
            id=fid,
            file=self.path,
            name=name,
            qualified_name=qualname,
            kind=kind,
            start_line=span.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
            # Whole lines, indentation included, so the source is exactly
            # start_line..end_line of the file.
            source=_source(self.data[span.start_byte - span.start_point[1]:span.end_byte]),
            is_async=bool(node.children) and node.children[0].type == "async",
        )
        outer.defs[name] = fid
        if outer.kind == "function":
            outer.locals.add(name)

        scope = Scope("function", qualname, outer, func_id=fid)
        self.scopes[qualname] = scope

        params = node.child_by_field_name("parameters")
        param_names = _parameter_names(params)
        scope.locals.update(param_names)
        scope.params = tuple(param_names)
        if outer.kind == "class":
            is_static = any(d.kind == "ref" and d.parts == ("staticmethod",) for d in decorators)
            if param_names and not is_static:
                scope.self_name = param_names[0]
                scope.self_class = outer.key
                scope.is_classmethod = any(
                    d.kind == "ref" and d.parts == ("classmethod",) for d in decorators
                )

        dependencies: tuple[Value, ...] = ()
        parameter_refs: list[Value] = []
        if params is not None:
            # Defaults and annotations run where the def statement runs.
            self._walk(params, outer)
            dependencies = tuple(self._dependency_calls(params))
            for p in params.named_children:
                annotation = p.child_by_field_name("type")
                for expr in (annotation.named_children[0] if annotation and annotation.named_children else None,
                             p.child_by_field_name("value")):
                    if expr is not None and expr.type in ("identifier", "attribute"):
                        parameter_refs.append(self._value(expr))
        return_type = node.child_by_field_name("return_type")
        if return_type is not None:
            self._walk(return_type, outer)

        self.functions.append(PyFunction(record, scope, outer, decorators, dependencies,
                                         tuple(parameter_refs)))
        body = node.child_by_field_name("body")
        if body is not None:
            self._walk(body, scope)

    def _class(self, node: Node, outer: Scope, span: Node) -> None:
        name = _text(node.child_by_field_name("name"))
        qualname = self._qualify(outer, name)
        outer.classes[name] = qualname
        if outer.kind == "function":
            outer.locals.add(name)

        bases = []
        superclasses = node.child_by_field_name("superclasses")
        if superclasses is not None:
            self._walk(superclasses, outer)
            for arg in superclasses.named_children:
                if arg.type in ("identifier", "attribute"):
                    bases.append(self._value(arg))

        scope = Scope("class", qualname, outer)
        self.scopes[qualname] = scope
        self.classes[qualname] = PyClass(qualname, scope, outer, tuple(bases))
        body = node.child_by_field_name("body")
        if body is not None:
            self._walk(body, scope)

    def _dependency_calls(self, params: Node) -> list[Value]:
        found = []
        stack = [params]
        while stack:
            n = stack.pop()
            if n.type == "call":
                parts = self._chain(n.child_by_field_name("function"))
                if parts[-1] in _DEPENDENCY_CALLS:
                    found.append(self._value(n, with_args=True))
            stack.extend(reversed(n.named_children))
        return found

    # -- imports -----------------------------------------------------------

    def _import(self, node: Node, scope: Scope) -> None:
        for child in node.named_children:
            if child.type == "dotted_name":
                dotted = _text(child)
                root = dotted.split(".")[0]
                scope.imports[root] = root
            elif child.type == "aliased_import":
                target = _text(child.child_by_field_name("name"))
                scope.imports[_text(child.child_by_field_name("alias"))] = target

    def _import_from(self, node: Node, scope: Scope) -> None:
        module = node.child_by_field_name("module_name")
        base = self._absolute_module(module)
        if base is None:
            return
        for child in node.named_children:
            if child == module:
                continue
            if child.type == "wildcard_import":
                scope.stars.append(base)
            elif child.type == "dotted_name":
                name = _text(child)
                scope.imports[name.split(".")[-1]] = _join(base, name)
            elif child.type == "aliased_import":
                name = _text(child.child_by_field_name("name"))
                scope.imports[_text(child.child_by_field_name("alias"))] = _join(base, name)

    def _absolute_module(self, module: Node | None) -> str | None:
        """`from <module> import ...` -> the absolute dotted module name.
        Relative imports are resolved against this file's package."""
        if module is None:
            return None
        if module.type != "relative_import":
            return _text(module)
        prefix = next((c for c in module.named_children if c.type == "import_prefix"), None)
        dotted = next((c for c in module.named_children if c.type == "dotted_name"), None)
        level = len(_text(prefix).strip())
        package = self.name.split(".") if self.name else []
        if not self.is_package:
            package = package[:-1]
        if level - 1 > len(package):
            return None
        if level > 1:
            package = package[: len(package) - (level - 1)]
        if dotted is not None:
            package = package + _text(dotted).split(".")
        return ".".join(package)

    # -- calls and assignments ---------------------------------------------

    def _caller(self, scope: Scope) -> str:
        fid = self._runs_in(scope)
        if fid.endswith(f"::{MODULE_SCOPE}"):
            self.module_calls = True
        return fid

    def _runs_in(self, scope: Scope) -> str:
        """The function (or <module>) whose code `scope` runs as part of."""
        s: Scope | None = scope
        while s is not None:
            if s.kind == "function":
                return s.func_id  # type: ignore[return-value]
            s = s.parent
        return function_id(self.path, MODULE_SCOPE)

    def _call(self, node: Node, scope: Scope) -> None:
        parts = self._chain(node.child_by_field_name("function"))
        value = self._value(node, with_args=parts[-1] in _KEEP_ARGS, parts=parts)
        raw = RawCall(self._caller(scope), scope, value)
        self.calls.append(raw)
        self._pending_calls.append((raw, node))

    def _flow(self, scope: Scope, target: Node | None, how: str, value: Node | None) -> None:
        """Remember that the names in `target` take their value from `value`."""
        if target is None or value is None:
            return
        stack = [target]
        while stack:
            n = stack.pop()
            if n.type == "identifier":
                self._flows.setdefault((id(scope), _text(n)), []).append((how, value))
            elif n.type in _PATTERN_TYPES:
                stack.extend(n.named_children)

    def _assignment(self, node: Node, scope: Scope) -> None:
        left = node.child_by_field_name("left")
        self._bind(left, scope)
        right = node.child_by_field_name("right")
        while right is not None and right.type == "assignment":   # a = b = X()
            right = right.child_by_field_name("right")
        if left is None or right is None:
            return
        if left.type in ("pattern_list", "tuple_pattern", "tuple"):
            self._flow(scope, left, "flow", right)
            return
        target = left
        if left.type == "attribute":                      # self.api_key = "..."
            target = left.child_by_field_name("attribute")
        if target is not None and target.type == "identifier" and right.type in (
                "string", "concatenated_string"):
            self._pending_assigns.append((scope, _text(target), right, node))
        if left.type != "identifier":
            return
        self._flow(scope, left, "assign", right)
        name = _text(left)
        scope.assigns.setdefault(name, []).append(self._value(right, with_args=True))
        deps = self._dependency_calls(right)
        if deps:
            scope.dependency_aliases[name] = tuple(deps)

    # -- facts for the rules -----------------------------------------------

    def _complete_facts(self) -> list[AssignFact]:
        for raw, node in self._pending_calls:
            raw.site = self._site(node)
            args: list[ArgFact] = []
            kwargs: list[tuple[str, ArgFact]] = []
            arguments = node.child_by_field_name("arguments")
            if arguments is not None and arguments.type == "argument_list":
                for arg in arguments.named_children:
                    if arg.type == "keyword_argument":
                        val = arg.child_by_field_name("value")
                        if val is not None:
                            kwargs.append((_text(arg.child_by_field_name("name")),
                                           self._fact(val, raw.scope)))
                    elif arg.type not in ("list_splat", "dictionary_splat", "comment"):
                        args.append(self._fact(arg, raw.scope))
            elif arguments is not None:                    # f(x for x in y)
                args.append(self._fact(arguments, raw.scope))
            raw.args, raw.kwargs = tuple(args), tuple(kwargs)

        assignments = [
            AssignFact(self._runs_in(scope), name, self._fact(value, scope), self._site(stmt))
            for scope, name, value, stmt in self._pending_assigns
        ]
        self._flows.clear()
        self._pending_calls.clear()
        self._pending_assigns.clear()
        return assignments

    def _site(self, node: Node) -> SiteFacts:
        line = node.start_point[0] + 1
        end_line = node.end_point[0] + 1
        last = min(end_line, line + _SNIPPET_LINES - 1)
        start = self._line_starts[line - 1]
        stop = self._line_starts[last] - 1 if last < len(self._line_starts) else len(self.data)
        prefix = self.data[start:start + node.start_point[1]].decode("utf-8", "replace")
        return SiteFacts(
            file=self.path, line=line, column=len(prefix) + 1, end_line=end_line,
            snippet=_source(self.data[start:stop]).rstrip("\r\n"),
        )

    def _fact(self, node: Node, scope: Scope) -> ArgFact:
        kind, how, via, value = self._kind(node, scope, frozenset(), 0)
        ref = ".".join(self._chain(node)) if node.type in ("identifier", "attribute") else None
        return ArgFact(kind=kind, text=node.text[:_TEXT_LIMIT].decode("utf-8", "replace"),
                       how=how, via=via, params=tuple(sorted(self._params(node, scope))),
                       value=value, ref=ref)

    @staticmethod
    def _binding_scopes(scope: Scope):
        """The scopes a name used in `scope` can be bound in, innermost first:
        the scope itself, enclosing functions, then the module."""
        s: Scope | None = scope
        first = True
        while s is not None:
            if first or s.kind != "class":
                yield s
            first = False
            s = s.parent

    def _kind(self, node: Node, scope: Scope, seen: frozenset, depth: int):
        """(kind, how, via, constant value) of an expression; see ArgFact."""
        t = node.type
        if depth > _MAX_DEPTH:
            return "other", None, None, None
        if t in ("string", "concatenated_string"):
            parts = node.named_children if t == "concatenated_string" else [node]
            pieces = [_string_literal(p) for p in parts]
            if all(p is not None for p in pieces):
                return "literal", None, None, "".join(pieces)  # type: ignore[arg-type]
            # An f-string is only built at run time if a placeholder is: one
            # that interpolates constants (f"{SCHEMA}", SCHEMA = "core") is not.
            holes = [c.child_by_field_name("expression") for p in parts
                     for c in p.named_children if c.type == "interpolation"]
            if all(h is not None and self._kind(h, scope, seen, depth + 1)[0] == "literal" for h in holes):
                return "literal", None, None, None
            return "built", "fstring", None, None
        if t in _LITERAL_TYPES:
            return "literal", None, None, {"true": True, "false": False, "none": None}.get(t, _text(node))
        if t == "parenthesized_expression" and node.named_children:
            return self._kind(node.named_children[0], scope, seen, depth + 1)
        if t in ("list", "tuple", "set"):
            kinds = [self._kind(c, scope, seen, depth + 1)[0] for c in node.named_children]
            return ("literal" if all(k == "literal" for k in kinds) else "other"), None, None, None
        if t == "binary_operator":
            operands = [node.child_by_field_name("left"), node.child_by_field_name("right")]
            kinds = [self._kind(o, scope, seen, depth + 1)[0] for o in operands if o is not None]
            if all(k == "literal" for k in kinds):
                return "literal", None, None, None
            how = {"+": "concat", "%": "percent"}.get(_text(node.child_by_field_name("operator")))
            return ("built", how, None, None) if how else ("other", None, None, None)
        if t == "conditional_expression":
            kinds = [self._kind(c, scope, seen, depth + 1) for c in node.named_children]
            built = next((k for k in kinds if k[0] == "built"), None)
            if built is not None:
                return built
            if all(k[0] == "literal" for k in kinds):
                return "literal", None, None, None
            return "other", None, None, None
        if t == "call":
            func = node.child_by_field_name("function")
            if func is not None and func.type == "attribute":
                method = _text(func.child_by_field_name("attribute"))
                if method in ("format", "join"):
                    inputs = [func.child_by_field_name("object")]
                    arguments = node.child_by_field_name("arguments")
                    if arguments is not None:
                        inputs += [a.child_by_field_name("value") if a.type == "keyword_argument" else a
                                   for a in arguments.named_children if a.type != "comment"]
                    kinds = [self._kind(i, scope, seen, depth + 1)[0] for i in inputs if i is not None]
                    if all(k == "literal" for k in kinds):
                        return "literal", None, None, None
                    return "built", method, None, None
            return "other", None, None, None
        if t == "identifier":
            return self._name_kind(_text(node), scope, seen, depth)
        return "other", None, None, None

    def _name_kind(self, name: str, scope: Scope, seen: frozenset, depth: int):
        for s in self._binding_scopes(scope):
            key = (id(s), name)
            if key in seen:
                return "other", None, None, None
            flows = self._flows.get(key)
            if flows:
                results = []
                for how, value in flows:
                    if how == "flow":                      # for x in ..., with ... as x
                        results.append(("other", None))
                        continue
                    kind, built_how, _, _ = self._kind(value, s, seen | {key}, depth + 1)
                    if how.startswith("aug") and kind != "literal":
                        built_how = {"aug+=": "concat", "aug%=": "percent"}.get(how)
                        kind = "built" if built_how else "other"
                    results.append((kind, built_how))
                built = next((r for r in results if r[0] == "built"), None)
                if built is not None:
                    return "built", built[1], name, None
                if all(r[0] == "literal" for r in results):
                    return "literal", None, name, None
                if all(r[0] in ("param", "literal") for r in results):
                    return "param", None, name, None
                return "other", None, name, None
            if s.kind == "function":
                if name in s.params:
                    return "param", None, None, None
                if name in s.locals and name not in s.globals:
                    return "other", None, None, None
        return "other", None, None, None

    def _params(self, node: Node, scope: Scope) -> set[str]:
        """Parameters (of this function or an enclosing one) that the value of
        `node` derives from, following local assignments."""
        found: set[str] = set()
        seen: set[tuple[int, str]] = set()
        work: list[tuple[Node, Scope]] = [(node, scope)]
        while work:
            n, sc = work.pop()
            stack = [n]
            while stack:
                cur = stack.pop()
                if cur.type in ("lambda", "function_definition", "class_definition"):
                    continue
                if cur.type != "identifier":
                    stack.extend(cur.named_children)
                    continue
                parent = cur.parent
                if parent is not None and (
                        (parent.type == "attribute" and parent.child_by_field_name("attribute") == cur)
                        or (parent.type == "keyword_argument" and parent.child_by_field_name("name") == cur)):
                    continue
                name = _text(cur)
                for s in self._binding_scopes(sc):
                    key = (id(s), name)
                    flows = self._flows.get(key)
                    if flows:
                        if key not in seen:
                            seen.add(key)
                            work.extend((value, s) for _, value in flows)
                        break
                    if s.kind == "function" and name in s.params:
                        found.add(name)
                        break
                    if s.kind == "function" and name in s.locals:
                        break
        return found

    # -- expressions -------------------------------------------------------

    def _chain(self, node: Node | None) -> tuple[str, ...]:
        """attribute/identifier chain -> its parts, root first. A root that is
        not a name becomes `callee()` for a call, else `<node type>`."""
        parts: list[str] = []
        while node is not None and node.type == "attribute":
            parts.append(_text(node.child_by_field_name("attribute")))
            node = node.child_by_field_name("object")
        if node is None:
            root = "<missing>"
        elif node.type == "identifier":
            root = _text(node)
        elif node.type == "call":
            root = ".".join(self._chain(node.child_by_field_name("function"))) + "()"
        else:
            root = f"<{node.type}>"
        parts.append(root)
        parts.reverse()
        return tuple(parts)

    def _value(self, node: Node, with_args: bool = False, parts: tuple[str, ...] | None = None) -> Value:
        t = node.type
        line = node.start_point[0] + 1
        text = node.text[:_TEXT_LIMIT].decode("utf-8", "replace")
        if t == "string":
            literal = _string_literal(node)
            if literal is not None:
                return Value("str", text, line, string=literal)
        elif t == "concatenated_string":
            pieces = [_string_literal(c) for c in node.named_children]
            if all(p is not None for p in pieces):
                return Value("str", text, line, string="".join(pieces))  # type: ignore[arg-type]
        elif t in ("list", "tuple"):
            items = tuple(self._value(c, with_args) for c in node.named_children)
            return Value("list", text, line, items=items)
        elif t in ("identifier", "attribute"):
            return Value("ref", text, line, parts=self._chain(node))
        elif t == "call":
            if parts is None:
                parts = self._chain(node.child_by_field_name("function"))
            args: list[Value] = []
            kwargs: list[tuple[str, Value]] = []
            arguments = node.child_by_field_name("arguments")
            if with_args and arguments is not None:
                if arguments.type != "argument_list":     # f(x for x in y)
                    args.append(Value("other", _text(arguments)[:_TEXT_LIMIT], line))
                else:
                    for arg in arguments.named_children:
                        if arg.type == "keyword_argument":
                            key = _text(arg.child_by_field_name("name"))
                            val = arg.child_by_field_name("value")
                            if val is not None:
                                kwargs.append((key, self._value(val, True)))
                        elif arg.type not in ("list_splat", "dictionary_splat", "comment"):
                            args.append(self._value(arg, True))
            return Value("call", text, line, parts=parts, args=tuple(args), kwargs=tuple(kwargs))
        return Value("other", text, line)


def _join(base: str, name: str) -> str:
    return f"{base}.{name}" if base else name


def _string_literal(node: Node) -> str | None:
    """The content of a plain string literal; None for f-strings and the like."""
    if node.type != "string":
        return None
    if any(c.type == "interpolation" for c in node.named_children):
        return None
    return "".join(_text(c) for c in node.named_children if c.type == "string_content")


def _parameter_names(params: Node | None) -> list[str]:
    names: list[str] = []
    if params is None:
        return names
    for p in params.named_children:
        if p.type in ("default_parameter", "typed_default_parameter"):
            p = p.child_by_field_name("name")
        elif p.type == "typed_parameter":            # `x: int`, `*args: int`
            p = p.named_children[0] if p.named_children else None
        if p is not None and p.type in ("list_splat_pattern", "dictionary_splat_pattern"):
            p = next((c for c in p.named_children if c.type == "identifier"), None)
        if p is not None and p.type == "identifier":
            names.append(_text(p))
    return names
