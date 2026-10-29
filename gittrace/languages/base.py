"""
gittrace.languages.base — the language plug-in interface and the
language-neutral records every plug-in produces.

A plug-in turns source files into these records; it never touches the graph.
gittrace.graph.store writes them to the project graph with the same schema
whatever the language, so adding a language means adding a plug-in, nothing else.

IDs follow the project rule: `relative/posix/path.py::QualifiedName`
(e.g. `app/db.py::Repo.get_user`). Two pseudo forms exist:

  - `path.py::<module>` — the code that runs at import time (module-level
    statements, decorators, default arguments). Only created for files that
    make calls at module level.
  - `external::<dotted.name>` — a call that could not be resolved to project
    code (e.g. `external::subprocess.run`). These are the sink candidates.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Sequence

MODULE_SCOPE = "<module>"
EXTERNAL_PREFIX = "external::"


def function_id(path: str, qualified_name: str) -> str:
    return f"{path}::{qualified_name}"


def external_id(dotted: str) -> str:
    return f"{EXTERNAL_PREFIX}{dotted}"


@dataclass(frozen=True)
class SourceFile:
    """A file handed to a plug-in: its project-relative POSIX path and raw bytes."""

    path: str
    data: bytes


@dataclass(frozen=True)
class FileRecord:
    path: str
    language: str
    sha256: str
    lines: int
    doc: str | None = None    # the module docstring's first paragraph (for `explain`)


@dataclass(frozen=True)
class ParseFailure:
    path: str
    reason: str


@dataclass(frozen=True)
class FunctionDef:
    id: str
    file: str
    name: str
    qualified_name: str
    kind: str            # function | method | nested | module
    start_line: int      # 1-based, includes decorators
    end_line: int        # 1-based, inclusive
    source: str
    is_async: bool = False
    doc: str | None = None    # the docstring's first paragraph (for `explain`)


@dataclass(frozen=True)
class ArgFact:
    """What a rule needs to know about one argument (or assigned value).

    kind:
      literal — a constant (string, number, bool, None, or an expression or
                variable built only from constants)
      built   — a string built at run time: f-string, `+`, `%`, `.format()`,
                `.join()`, or a variable assigned from one of those
      param   — a bare function parameter, passed through unchanged
      other   — anything else (a call result, an attribute, an unknown name)
    how:    for `built`, the construction (fstring | concat | percent | format | join)
    via:    the local variable the value came through, if any
    params: function parameters the value derives from (through local
            assignments, and enclosing functions' parameters for closures)
    value:  the constant, for a literal
    ref:    the dotted name, for a name or attribute (e.g. `yaml.SafeLoader`)
    """

    kind: str
    text: str
    how: str | None = None
    via: str | None = None
    params: tuple[str, ...] = ()
    value: object | None = None
    ref: str | None = None

    @property
    def is_literal(self) -> bool:
        return self.kind == "literal"


@dataclass(frozen=True)
class SiteFacts:
    """Where a call or assignment is, and what its source looks like."""

    file: str
    line: int
    column: int          # 1-based
    end_line: int
    snippet: str         # the whole source lines line..end_line


@dataclass(frozen=True)
class AssignFact:
    """A string constant bound to a name: `NAME = "..."`, `self.name = "..."`."""

    function_id: str     # the function (or <module>) the assignment runs in
    target: str          # the bound name; for an attribute, the attribute name
    value: ArgFact
    site: SiteFacts


@dataclass(frozen=True)
class CallSite:
    """One call expression.

    `callee_id` is set when the call resolved to a project function. Otherwise
    `dotted` is the best full name for the callee (aliases expanded, e.g.
    `sp.run` -> `subprocess.run`) and `origin` says where that name came from:
      builtin  — a Python builtin (eval, exec, print, ...)
      import   — rooted in an imported module that is not project code
      project  — rooted in project code but not resolvable to a function
      unknown  — rooted in a local variable or an expression (cursor.execute)
      class    — instantiates a project class with no __init__ of its own;
                 no project code runs, so no edge is written for it
      dynamic  — an immediate `getattr(obj, name)()` whose receiver and name
                 could not be pinned down: a documented marker, kept so the
                 dispatch is visible instead of dropped

    `dynamic` marks every site that came from `getattr` dispatch: with a
    literal attribute name it is the direct edge the literal `obj.name()`
    would give, with a computed name it is a low-confidence edge to each
    member the receiver could hold (see gittrace.languages.python.resolver).
    It also marks the edge to a thread's target (`threading.Thread(target=f)`
    calls `f`), the other call that is not written as one.
    Reachability and blast radius traverse those edges like any other; the
    flag is what says the target set was inferred rather than named.
    """

    caller_id: str
    line: int
    dotted: str
    origin: str
    callee_id: str | None = None
    site: SiteFacts | None = None
    args: tuple[ArgFact, ...] = ()
    kwargs: tuple[tuple[str, ArgFact], ...] = ()
    dynamic: bool = False

    @property
    def resolved(self) -> bool:
        return self.callee_id is not None

    def kwarg(self, name: str) -> ArgFact | None:
        for key, value in self.kwargs:
            if key == name:
                return value
        return None

    def argument(self, position: int, *names: str) -> ArgFact | None:
        """The argument at `position`, or the first of `names` passed by keyword."""
        if position < len(self.args):
            return self.args[position]
        for name in names:
            found = self.kwarg(name)
            if found is not None:
                return found
        return None


@dataclass(frozen=True)
class EndpointDef:
    id: str
    framework: str           # fastapi | flask
    method: str              # GET, POST, ..., WEBSOCKET
    path: str
    handler_id: str
    file: str
    line: int                # line of the route decorator
    auth_required: bool
    auth_evidence: tuple[str, ...] = ()
    # False when some part of the prefix chain was not resolved: a router
    # that is never included, or a prefix that is not a string literal.
    prefix_resolved: bool = True


def endpoint_id(method: str, path: str, handler_id: str) -> str:
    return f"{method} {path} -> {handler_id}"


# -- facts for `gittrace explain` ---------------------------------------------

@dataclass(frozen=True)
class ImportFact:
    """One imported module. kind: project (a file of the project) | stdlib |
    external (a third-party package); `package` is its top-level name."""

    file: str
    line: int
    module: str
    kind: str
    package: str


@dataclass(frozen=True)
class EntryPointDef:
    """Where the program starts, other than an HTTP route.

    kind:
      main         `if __name__ == "__main__":` (function_id is the file's <module>)
      cli          a command-line command (click / Typer command, argparse parser)
      app          a web application object created at import time
      app_factory  a function that creates a web application object
    """

    kind: str
    function_id: str
    file: str
    line: int
    detail: str


# Side-effect kinds, as explained to readers of `explain`.
EFFECT_KINDS = {
    "db_read": "reads the database",
    "db_write": "writes the database",
    "db": "uses the database",
    "store_read": "reads a search index, cache or queue",
    "store_write": "writes a search index, cache or queue",
    "network": "calls another service over the network",
    "file_read": "reads files",
    "file_write": "writes or deletes files",
    "subprocess": "runs other programs",
}


@dataclass(frozen=True)
class EffectFact:
    """A call with a side effect outside the program (EFFECT_KINDS)."""

    function_id: str
    file: str
    line: int
    kind: str
    callee: str          # the dotted name called, e.g. `cursor.execute`
    detail: str = ""     # e.g. `SQL SELECT`, `mode "w"`


@dataclass(frozen=True)
class ServiceFact:
    """A data store or outside service the project uses.

    kind: database | cache | search | http | email | queue | cloud | ai |
          payments | files | programs
    """

    kind: str
    name: str            # e.g. "SQLite", "outbound HTTP (requests)"
    explanation: str     # one plain sentence for someone new to the term
    evidence: tuple[str, ...]   # `app/db.py:1 imports sqlite3`, ...


@dataclass
class ProjectFacts:
    """What a plug-in's `project_facts` returns."""

    imports: list[ImportFact] = field(default_factory=list)
    entry_points: list[EntryPointDef] = field(default_factory=list)
    effects: list[EffectFact] = field(default_factory=list)
    services: list[ServiceFact] = field(default_factory=list)


@dataclass
class ParsedProject:
    """What a plug-in's parse step returns. Plug-ins subclass it to carry
    whatever they need for call resolution and route detection."""

    files: list[FileRecord] = field(default_factory=list)
    functions: list[FunctionDef] = field(default_factory=list)
    failures: list[ParseFailure] = field(default_factory=list)
    assignments: list[AssignFact] = field(default_factory=list)
    # Every file's <module> record, by id. Only files that call at import
    # time have theirs in `functions`; a finding at module level adds it.
    module_scopes: dict[str, FunctionDef] = field(default_factory=dict)


class LanguagePlugin(ABC):
    """One language: a parser, a call resolver, a route detector and a rule
    set, all working on the plug-in's own ParsedProject. The parser turns
    calls and assignments into the language-neutral CallSite / AssignFact
    records; rules (gittrace.rules) only ever see those."""

    name: str
    extensions: tuple[str, ...]

    @abstractmethod
    def parse(self, sources: Sequence[SourceFile]) -> ParsedProject:
        """Parse every file. A file that fails to parse goes to `failures`
        and contributes nothing else; it must not stop the others."""

    @abstractmethod
    def resolve_calls(self, parsed: ParsedProject) -> list[CallSite]:
        """Every call site, resolved to a project function where possible."""

    @abstractmethod
    def detect_routes(self, parsed: ParsedProject) -> list[EndpointDef]:
        """Public HTTP routes and the functions that handle them."""

    def rules(self) -> Sequence[object]:
        """The vulnerability rules (gittrace.rules.base.Rule) for this language."""
        from gittrace.rules import rules_for

        return rules_for(self.name)

    def project_facts(self, parsed: ParsedProject, calls: Sequence[CallSite]) -> ProjectFacts:
        """Imports, entry points, side effects and services, for `explain`.
        A plug-in that does not know them returns nothing (not a guess)."""
        return ProjectFacts()
