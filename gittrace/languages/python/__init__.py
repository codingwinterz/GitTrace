"""Python support: tree-sitter parsing, call resolution and FastAPI/Flask route detection."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Sequence

from gittrace.languages.base import (
    CallSite,
    EndpointDef,
    LanguagePlugin,
    ParsedProject,
    ParseFailure,
    ProjectFacts,
    SourceFile,
)
from gittrace.languages.python import facts
from gittrace.languages.python.parser import ParseError, PyModule, parse_module
from gittrace.languages.python.resolver import Resolver
from gittrace.languages.python.routes import detect_routes

log = logging.getLogger(__name__)


@dataclass
class PythonProject(ParsedProject):
    modules: list[PyModule] = field(default_factory=list)
    _resolver: Resolver | None = None

    @property
    def resolver(self) -> Resolver:
        if self._resolver is None:
            self._resolver = Resolver(self.modules)
        return self._resolver


class PythonPlugin(LanguagePlugin):
    name = "python"
    extensions = (".py",)

    def parse(self, sources: Sequence[SourceFile]) -> PythonProject:
        project = PythonProject()
        for source in sources:
            try:
                module = parse_module(source.path, source.data)
            except ParseError as exc:
                log.debug("skipping %s: %s", source.path, exc)       # reported in the summary
                project.failures.append(ParseFailure(source.path, str(exc)))
                continue
            except Exception as exc:  # noqa: BLE001 - one bad file must not stop the scan
                log.debug("skipping %s: %s: %s", source.path, type(exc).__name__, exc)
                project.failures.append(ParseFailure(source.path, f"{type(exc).__name__}: {exc}"))
                continue
            project.modules.append(module)
            project.files.append(module.record)
            if module.module_function is not None:
                project.functions.append(module.module_function)
            project.functions.extend(f.record for f in module.functions)
            project.assignments.extend(module.assignments)
            if module.module_scope is not None:
                project.module_scopes[module.module_scope.id] = module.module_scope
        return project

    def resolve_calls(self, parsed: ParsedProject) -> list[CallSite]:
        assert isinstance(parsed, PythonProject)
        resolver = parsed.resolver
        return [resolver.resolve_call(m, c) for m in parsed.modules for c in m.calls]

    def detect_routes(self, parsed: ParsedProject) -> list[EndpointDef]:
        assert isinstance(parsed, PythonProject)
        return detect_routes(parsed.modules, parsed.resolver)

    def project_facts(self, parsed: ParsedProject, calls: Sequence[CallSite]) -> ProjectFacts:
        assert isinstance(parsed, PythonProject)
        imports = facts.imports(parsed.modules, parsed.resolver)
        effects = facts.effects(calls, facts.receiver_types(parsed.modules, parsed.resolver))
        return ProjectFacts(imports=imports,
                            entry_points=facts.entry_points(parsed.modules, parsed.resolver, calls),
                            effects=effects, services=facts.services(imports, effects))
