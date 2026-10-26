"""
gittrace.core.explain — the deterministic facts behind `gittrace explain`.

Everything here comes from the analysis (gittrace.core.pipeline) and the
rule findings (gittrace.core.scan, offline); nothing calls a model, so it all
works with --no-llm. The model layer (gittrace.llm.explain) only writes
plain-language summaries on top of these facts.

  project   entry points (`__main__`, CLI commands, app objects and
            factories), the endpoints table, modules grouped by folder,
            third-party libraries, data stores and outside services
  file      its functions, imports, endpoints, entry points, side effects
            and findings
  function  its callers and the project functions it calls, its library
            calls, the side effects of its own calls, the side effects
            reached through the project functions it calls (within --depth
            hops), the endpoints it handles, and its findings
  flow      per handler, a tree of the project functions it calls,
            depth-limited, each with its library calls collapsed onto one
            line; a function already shown in the tree is not expanded again

Important functions (summarised by default; --all summarises every one):
route handlers, entry points, and functions called from at least
`min_callers` other functions. A file's import-time code (`<module>`) is
part of its file, never summarised as a function.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field

from gittrace.languages.base import EFFECT_KINDS, MODULE_SCOPE

DEFAULT_FLOW_DEPTH = 4
MAX_FLOW_DEPTH = 10
DEFAULT_MIN_CALLERS = 3
DEFAULT_EFFECT_DEPTH = 5
MAX_LIBRARY_CALLS = 8


@dataclass
class FunctionInfo:
    id: str
    file: str
    name: str
    qualified_name: str
    kind: str
    start_line: int
    end_line: int
    doc: str | None
    callers: list[str] = field(default_factory=list)          # project function ids
    callees: list[str] = field(default_factory=list)          # in order of the first call
    library_calls: list[str] = field(default_factory=list)    # dotted names, first-call order
    effects: list = field(default_factory=list)               # EffectFact, its own calls
    effects_via: dict[str, list[str]] = field(default_factory=dict)   # kind -> functions doing it
    endpoints: list = field(default_factory=list)             # EndpointDef it handles
    entry_points: list = field(default_factory=list)          # EntryPointDef
    findings: list[dict] = field(default_factory=list)
    important_because: list[str] = field(default_factory=list)

    @property
    def is_module(self) -> bool:
        return self.qualified_name == MODULE_SCOPE

    @property
    def effect_kinds(self) -> list[str]:
        return sorted({e.kind for e in self.effects}, key=list(EFFECT_KINDS).index)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "file": self.file, "qualified_name": self.qualified_name, "kind": self.kind,
            "lines": [self.start_line, self.end_line], "doc": self.doc,
            "callers": self.callers, "calls": self.callees, "library_calls": self.library_calls,
            "side_effects": [{"line": e.line, "kind": e.kind, "what": EFFECT_KINDS[e.kind],
                              "call": e.callee, "detail": e.detail} for e in self.effects],
            "side_effects_through_calls": self.effects_via,
            "handles": [{"method": e.method, "path": e.path, "auth_required": e.auth_required}
                        for e in self.endpoints],
            "entry_points": [{"kind": e.kind, "detail": e.detail} for e in self.entry_points],
            "findings": self.findings,
            "important_because": self.important_because,
        }


@dataclass
class FileInfo:
    path: str
    lines: int
    doc: str | None
    functions: list[str] = field(default_factory=list)       # ids, by line; no <module>
    imports_project: list[str] = field(default_factory=list)
    imports_external: list[str] = field(default_factory=list)   # top-level packages
    imports_stdlib: list[str] = field(default_factory=list)
    endpoints: list = field(default_factory=list)
    entry_points: list = field(default_factory=list)
    effects: list = field(default_factory=list)               # every EffectFact in the file
    findings: list[dict] = field(default_factory=list)

    @property
    def effect_kinds(self) -> list[str]:
        return sorted({e.kind for e in self.effects}, key=list(EFFECT_KINDS).index)

    @property
    def folder(self) -> str:
        return self.path.rsplit("/", 1)[0] if "/" in self.path else "."

    def to_dict(self) -> dict:
        return {
            "path": self.path, "lines": self.lines, "doc": self.doc, "functions": self.functions,
            "imports": {"project": self.imports_project, "external": self.imports_external,
                        "stdlib": self.imports_stdlib},
            "endpoints": [{"method": e.method, "path": e.path, "handler": e.handler_id,
                           "auth_required": e.auth_required} for e in self.endpoints],
            "entry_points": [{"kind": e.kind, "function": e.function_id, "line": e.line, "detail": e.detail}
                             for e in self.entry_points],
            "side_effects": dict(Counter(e.kind for e in self.effects)),
            "findings": self.findings,
        }


@dataclass
class FlowNode:
    function_id: str
    label: str
    library_calls: list[str]
    effect_kinds: list[str]
    children: list["FlowNode"] = field(default_factory=list)
    note: str | None = None          # "shown above", "N more calls below depth D"

    def to_dict(self) -> dict:
        return {"function": self.function_id, "library_calls": self.library_calls,
                "side_effects": self.effect_kinds, "note": self.note,
                "calls": [c.to_dict() for c in self.children]}


@dataclass
class Flow:
    endpoints: list                  # EndpointDef, all handled by the root
    root: FlowNode

    def to_dict(self) -> dict:
        return {"endpoints": [{"method": e.method, "path": e.path, "auth_required": e.auth_required}
                              for e in self.endpoints],
                "tree": self.root.to_dict()}


@dataclass
class ProjectExplanation:
    """Every deterministic fact `explain` shows."""

    project: str
    root: str
    files: dict[str, FileInfo]
    functions: dict[str, FunctionInfo]
    endpoints: list
    entry_points: list
    services: list
    libraries: dict[str, list[str]]          # package -> files importing it
    folders: dict[str, list[str]]            # folder -> files
    findings: list[dict]
    parse_failures: list
    flow_depth: int
    min_callers: int

    def important(self) -> list[FunctionInfo]:
        return [f for f in self.functions.values() if f.important_because and not f.is_module]

    def summarisable(self) -> list[FunctionInfo]:
        return [f for f in self.functions.values() if not f.is_module]

    def to_dict(self) -> dict:
        return {
            "project": self.project,
            "entry_points": [{"kind": e.kind, "function": e.function_id, "file": e.file, "line": e.line,
                              "detail": e.detail} for e in self.entry_points],
            "endpoints": [{"method": e.method, "path": e.path, "auth_required": e.auth_required,
                           "auth_evidence": list(e.auth_evidence), "handler": e.handler_id,
                           "prefix_resolved": e.prefix_resolved} for e in self.endpoints],
            "modules": self.folders,
            "libraries": self.libraries,
            "services": [{"kind": s.kind, "name": s.name, "explanation": s.explanation,
                          "evidence": list(s.evidence)} for s in self.services],
            "parse_failures": [{"file": f.path, "reason": f.reason} for f in self.parse_failures],
            "findings": self.findings,
        }


# Builtins that say nothing about what a function does; others (eval, exec,
# open, __import__, input, ...) are shown with the library calls.
_TRIVIAL_BUILTINS = frozenset({
    "abs", "all", "any", "bool", "bytes", "callable", "dict", "dir", "divmod", "enumerate", "filter",
    "float", "format", "frozenset", "getattr", "hasattr", "hash", "id", "int", "isinstance", "issubclass",
    "iter", "len", "list", "map", "max", "min", "next", "object", "ord", "chr", "print", "range", "repr",
    "reversed", "round", "set", "setattr", "slice", "sorted", "str", "sum", "super", "tuple", "type",
    "vars", "zip", "property", "staticmethod", "classmethod", "delattr", "bytearray", "complex", "hex",
    "oct", "bin", "pow", "ascii", "memoryview",
})


def _worth_showing(call) -> bool:
    if call.origin == "class" or call.dotted.startswith("<"):
        return False
    if call.origin == "builtin":
        return call.dotted not in _TRIVIAL_BUILTINS
    return True


def _finding_dict(f) -> dict:
    return {"id": f.id, "rule_id": f.rule_id, "title": f.title, "severity": f.severity,
            "file": f.file, "line": f.line, "function": f.function_id, "in_tests": f.in_tests}


def build(result, min_callers: int = DEFAULT_MIN_CALLERS, flow_depth: int = DEFAULT_FLOW_DEPTH,
          effect_depth: int = DEFAULT_EFFECT_DEPTH) -> ProjectExplanation:
    """The facts for a scan result (gittrace.core.scan.scan, offline)."""
    analysis = result.analysis
    defs = dict(analysis.module_scopes)
    defs.update({f.id: f for f in analysis.functions})
    functions: dict[str, FunctionInfo] = {}
    for f in sorted(defs.values(), key=lambda d: (d.file, d.start_line, d.id)):
        if f.qualified_name == MODULE_SCOPE and f.id not in {x.id for x in analysis.functions}:
            continue        # a file that does nothing at import time
        functions[f.id] = FunctionInfo(f.id, f.file, f.name, f.qualified_name, f.kind, f.start_line,
                                       f.end_line, f.doc)

    callees: dict[str, dict[str, int]] = defaultdict(dict)
    for call in sorted(analysis.calls, key=lambda c: (c.caller_id, c.line)):
        info = functions.get(call.caller_id)
        if info is None:
            continue
        if call.resolved:
            if call.callee_id != call.caller_id and call.callee_id in functions:
                callees[call.caller_id].setdefault(call.callee_id, call.line)
                caller_list = functions[call.callee_id].callers
                if call.caller_id not in caller_list:
                    caller_list.append(call.caller_id)
        elif _worth_showing(call) and call.dotted not in info.library_calls:
            info.library_calls.append(call.dotted)
    for fid, called in callees.items():
        functions[fid].callees = list(called)
    for info in functions.values():
        info.callers.sort()
        # `conn.execute(sql).fetchall()` reads as `conn.execute` (and the fetch)
        info.library_calls = [d for d in info.library_calls
                              if "()." not in d or d.split("().", 1)[0] not in info.library_calls]

    for e in analysis.effects:
        if e.function_id in functions:
            functions[e.function_id].effects.append(e)
    for info in functions.values():
        info.effects_via = _effects_via(info.id, functions, effect_depth)

    for e in analysis.endpoints:
        if e.handler_id in functions:
            functions[e.handler_id].endpoints.append(e)
    for e in analysis.entry_points:
        if e.function_id in functions:
            functions[e.function_id].entry_points.append(e)

    all_findings = list(result.findings) + list(result.test_findings)
    for f in all_findings:
        if f.function_id in functions:
            functions[f.function_id].findings.append(_finding_dict(f))

    for info in functions.values():
        if info.is_module:
            continue
        reasons = [f"handles {e.method} {e.path}" for e in info.endpoints]
        reasons += [f"entry point: {e.detail}" for e in info.entry_points]
        outside = [c for c in info.callers if c != info.id]
        if len(outside) >= min_callers:
            reasons.append(f"called from {len(outside)} functions")
        info.important_because = reasons

    files: dict[str, FileInfo] = {}
    for rec in sorted(analysis.files, key=lambda r: r.path):
        files[rec.path] = FileInfo(rec.path, rec.lines, rec.doc)
    for info in functions.values():
        if not info.is_module and info.file in files:
            files[info.file].functions.append(info.id)
    for imp in analysis.imports:
        fi = files.get(imp.file)
        if fi is None:
            continue
        target = {"project": fi.imports_project, "external": fi.imports_external,
                  "stdlib": fi.imports_stdlib}[imp.kind]
        name = imp.module if imp.kind == "project" else imp.package
        if name not in target:
            target.append(name)
    for e in analysis.endpoints:
        if e.file in files:
            files[e.file].endpoints.append(e)
    for e in analysis.entry_points:
        if e.file in files:
            files[e.file].entry_points.append(e)
    for e in analysis.effects:
        if e.file in files:
            files[e.file].effects.append(e)
    for f in all_findings:
        if f.file in files:
            files[f.file].findings.append(_finding_dict(f))

    libraries: dict[str, list[str]] = defaultdict(list)
    for imp in analysis.imports:
        if imp.kind == "external" and imp.file not in libraries[imp.package]:
            libraries[imp.package].append(imp.file)
    folders: dict[str, list[str]] = defaultdict(list)
    for fi in files.values():
        folders[fi.folder].append(fi.path)

    endpoints = sorted(analysis.endpoints, key=lambda e: (e.path, e.method, e.handler_id))
    return ProjectExplanation(
        project=result.project, root=str(result.root), files=files, functions=functions,
        endpoints=endpoints, entry_points=list(analysis.entry_points), services=list(analysis.services),
        libraries=dict(sorted(libraries.items(), key=lambda kv: (-len(kv[1]), kv[0]))),
        folders=dict(sorted(folders.items())),
        findings=[_finding_dict(f) for f in all_findings], parse_failures=list(analysis.failures),
        flow_depth=flow_depth, min_callers=min_callers,
    )


def _effects_via(fid: str, functions: dict[str, FunctionInfo], depth: int) -> dict[str, list[str]]:
    """Side effects in the project functions `fid` calls, within `depth` hops."""
    out: dict[str, list[str]] = defaultdict(list)
    seen = {fid}
    frontier = [fid]
    for _ in range(depth):
        nxt = []
        for f in frontier:
            for c in functions[f].callees:
                if c not in seen:
                    seen.add(c)
                    nxt.append(c)
                    for kind in functions[c].effect_kinds:
                        if c not in out[kind]:
                            out[kind].append(c)
        frontier = nxt
    return {k: out[k] for k in EFFECT_KINDS if k in out}


def _label(info: FunctionInfo) -> str:
    return f"{info.qualified_name}  ({info.file}:{info.start_line})"


def flow(ex: ProjectExplanation, handler_id: str, depth: int | None = None) -> FlowNode:
    """The working-flow tree of one function: the project functions it calls,
    depth-limited. A function already shown in this tree is not expanded again."""
    depth = ex.flow_depth if depth is None else depth
    shown: set[str] = set()

    def node(fid: str, level: int) -> FlowNode:
        info = ex.functions[fid]
        n = FlowNode(fid, _label(info), info.library_calls[:MAX_LIBRARY_CALLS], info.effect_kinds)
        if len(info.library_calls) > MAX_LIBRARY_CALLS:
            n.library_calls.append(f"+{len(info.library_calls) - MAX_LIBRARY_CALLS} more")
        if fid in shown:
            n.note = "shown above"
            n.library_calls, n.effect_kinds = [], []
            return n
        shown.add(fid)
        if level >= depth:
            if info.callees:
                n.note = f"calls {len(info.callees)} more project function(s) below depth {depth}"
            return n
        n.children = [node(c, level + 1) for c in info.callees]
        return n

    return node(handler_id, 0)


def flows(ex: ProjectExplanation, depth: int | None = None) -> list[Flow]:
    """One flow per handler (endpoints sharing a handler share a flow), in endpoint order."""
    by_handler: dict[str, list] = {}
    for e in ex.endpoints:
        if e.handler_id in ex.functions:
            by_handler.setdefault(e.handler_id, []).append(e)
    return [Flow(eps, flow(ex, h, depth)) for h, eps in by_handler.items()]


def neighbours(ex: ProjectExplanation, fid: str) -> set[str]:
    """The functions a summary of `fid` may mention: itself, its callers and
    the project functions it calls (the grounding check, gittrace.llm.explain)."""
    info = ex.functions[fid]
    return {fid, *info.callers, *info.callees}


def file_neighbours(ex: ProjectExplanation, path: str) -> set[str]:
    """For a file summary: the file's functions, and their callers and callees."""
    out: set[str] = set()
    for fid in ex.files[path].functions + [f.id for f in ex.functions.values()
                                           if f.file == path and f.is_module]:
        out |= neighbours(ex, fid)
    return out
