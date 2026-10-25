"""
gittrace.languages.base — the language plug-in interface and the
language-neutral records every plug-in produces.

A plug-in turns source files into these records; it never touches the graph.
gittrace.graph.store writes them to FalkorDB with the same schema whatever the
language, so adding a language means adding a plug-in, nothing else.

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
    """

    caller_id: str
    line: int
    dotted: str
    origin: str
    callee_id: str | None = None

    @property
    def resolved(self) -> bool:
        return self.callee_id is not None


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


@dataclass
class ParsedProject:
    """What a plug-in's parse step returns. Plug-ins subclass it to carry
    whatever they need for call resolution and route detection."""

    files: list[FileRecord] = field(default_factory=list)
    functions: list[FunctionDef] = field(default_factory=list)
    failures: list[ParseFailure] = field(default_factory=list)


class LanguagePlugin(ABC):
    """One language: a parser, a call resolver, a route detector and (from
    Phase 4) a rule set, all working on the plug-in's own ParsedProject."""

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
        """Vulnerability rules for this language (Phase 4)."""
        return ()
