"""
gittrace.core.pipeline — scan a project folder into language-neutral records,
and optionally write them to the project's FalkorDB graph.

    analyze(path)  -> Analysis        offline: discover, parse, resolve, routes
    ingest(path)   -> (Analysis, graph name)   analyze + gittrace.graph.store
"""

from __future__ import annotations

import logging
import os
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from gittrace.core.discover import discover
from gittrace.languages import plugins
from gittrace.languages.base import (
    CallSite,
    EndpointDef,
    FileRecord,
    FunctionDef,
    ParseFailure,
    SourceFile,
)

log = logging.getLogger(__name__)


@dataclass
class Analysis:
    root: Path
    files: list[FileRecord] = field(default_factory=list)
    functions: list[FunctionDef] = field(default_factory=list)
    calls: list[CallSite] = field(default_factory=list)
    endpoints: list[EndpointDef] = field(default_factory=list)
    failures: list[ParseFailure] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        origins = Counter(c.origin for c in self.calls if not c.resolved)
        unresolved = [c for c in self.calls if not c.resolved and c.origin != "class"]
        return {
            "files": len(self.files),
            "parse_failures": len(self.failures),
            "functions": sum(1 for f in self.functions if f.kind != "module"),
            "module_scopes": sum(1 for f in self.functions if f.kind == "module"),
            "endpoints": len(self.endpoints),
            "calls": len(self.calls),
            "resolved_calls": sum(1 for c in self.calls if c.resolved),
            "unresolved_calls": len(unresolved),
            "class_instantiations": origins["class"],
            "unresolved_builtin": origins["builtin"],
            "unresolved_import": origins["import"],
            "unresolved_project": origins["project"],
            "unresolved_unknown": origins["unknown"],
            "external_callees": len({c.dotted for c in unresolved}),
        }


def analyze(root: str | os.PathLike) -> Analysis:
    root = Path(root).resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"not a directory: {root}")
    result = Analysis(root=root)
    for plugin in plugins():
        sources = []
        for rel in discover(root, plugin.extensions):
            try:
                sources.append(SourceFile(rel, (root / rel).read_bytes()))
            except OSError as exc:
                log.warning("skipping %s: %s", rel, exc)
                result.failures.append(ParseFailure(rel, f"unreadable: {exc}"))
        parsed = plugin.parse(sources)
        result.files.extend(parsed.files)
        result.functions.extend(parsed.functions)
        result.failures.extend(parsed.failures)
        result.calls.extend(plugin.resolve_calls(parsed))
        result.endpoints.extend(plugin.detect_routes(parsed))
    return result


def ingest(root: str | os.PathLike, db=None, graph_name: str | None = None) -> tuple[Analysis, str]:
    """Analyze `root` and rebuild its graph. Returns the analysis and the graph name."""
    from gittrace.graph import connection, store

    analysis = analyze(root)
    if db is None:
        db = connection.get_db()
    name = graph_name or store.graph_name_for(analysis.root)
    store.write_analysis(db.select_graph(name), analysis, name)
    return analysis, name
