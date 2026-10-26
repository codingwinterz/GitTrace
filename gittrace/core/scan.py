"""
gittrace.core.scan — `gittrace scan`: rule findings, reachability, severity, owner.

    1. analyze the project (gittrace.core.pipeline) and run the rules: each
       match is one Sink, identified by `path.py::line::col`;
    2. write the project graph with its Sink nodes (gittrace.graph.store);
    3. for each vulnerable function, ask the graph who reaches it
       (gittrace.core.reachability): upstream callers and endpoint routes;
    4. score each finding (gittrace.core.severity) and look up its owner
       with git blame (gittrace.core.owner);
    5. record the results on the Sink nodes.

With offline=True, steps 2 and 5 are skipped and step 3 runs in memory.

Findings in test code (a `tests`/`test` directory, test_*.py, *_test.py,
conftest.py) are reported separately at info severity and never fail a
`--fail-on` gate, unless include_tests=True treats them like any other code.
"""

from __future__ import annotations

import os
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from gittrace.core import pipeline
from gittrace.core.owner import Blamer, Owner
from gittrace.core.reachability import (
    DEFAULT_DEPTH,
    GraphReachability,
    MemoryReachability,
    Reach,
    Route,
    check_depth,
)
from gittrace.core.severity import Exposure, score
from gittrace.rules import run_rules
from gittrace.rules.base import SEVERITIES, Match, severity_rank


@dataclass(frozen=True)
class Finding:
    id: str
    rule_id: str
    category: str
    title: str
    severity: str
    score: int
    base_severity: str
    reasons: tuple[str, ...]
    file: str
    line: int
    column: int
    end_line: int
    snippet: str
    function_id: str
    callee: str | None
    message: str
    evidence: tuple[str, ...]
    param_derived: bool
    params: tuple[str, ...]
    flow_sensitive: bool
    routes: tuple[Route, ...]
    callers: tuple[str, ...]
    uncertain: bool
    owner: Owner | None = None
    in_tests: bool = False          # in test code, reported separately at info

    @property
    def reachable(self) -> bool:
        return bool(self.routes)

    @property
    def unauthenticated(self) -> bool:
        return any(not r.auth_required for r in self.routes)

    @property
    def blast_radius(self) -> int:
        return len(self.callers) + len(self.routes)

    def sort_key(self):
        return (-severity_rank(self.severity), -self.score, not self.unauthenticated,
                not self.reachable, self.file, self.line, self.column, self.rule_id)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "category": self.category,
            "title": self.title,
            "severity": self.severity,
            "score": self.score,
            "base_severity": self.base_severity,
            "reasons": list(self.reasons),
            "location": {"file": self.file, "line": self.line, "column": self.column,
                         "end_line": self.end_line},
            "snippet": self.snippet,
            "function": self.function_id,
            "callee": self.callee,
            "message": self.message,
            "evidence": list(self.evidence),
            "param_derived": self.param_derived,
            "params": list(self.params),
            "reachability": {
                "applies": self.flow_sensitive,
                "reachable": self.reachable,
                "unauthenticated": self.unauthenticated,
                "uncertain": self.uncertain,
                "routes": [{
                    "endpoint": r.endpoint_id, "method": r.method, "path": r.path,
                    "auth_required": r.auth_required, "prefix_resolved": r.prefix_resolved,
                    "hops": r.hops, "path_nodes": list(r.nodes),
                } for r in self.routes],
            },
            "blast_radius": {
                "total": self.blast_radius,
                "callers": list(self.callers),
                "endpoints": len(self.routes),
            },
            "in_tests": self.in_tests,
            "owner": None if self.owner is None else {
                "status": self.owner.status, "author": self.owner.author,
                "email": self.owner.email, "commit": self.owner.commit,
                "date": self.owner.date, "summary": self.owner.summary,
            },
        }


@dataclass
class ScanResult:
    project: str
    root: Path
    graph: str | None
    depth: int
    findings: list[Finding]
    analysis: pipeline.Analysis = field(repr=False)
    test_findings: list[Finding] = field(default_factory=list)

    def at_least(self, minimum: str) -> list[Finding]:
        floor = severity_rank(minimum)
        return [f for f in self.findings if severity_rank(f.severity) >= floor]

    def summary(self, findings: list[Finding] | None = None) -> dict:
        findings = self.findings if findings is None else findings
        levels = Counter(f.severity for f in findings)
        return {
            "total": len(findings),
            "by_severity": {level: levels.get(level, 0) for level in reversed(SEVERITIES)},
            "by_rule": dict(sorted(Counter(f.rule_id for f in findings).items())),
            "reachable": sum(1 for f in findings if f.reachable),
            "unauthenticated": sum(1 for f in findings if f.unauthenticated),
        }

    def to_dict(self, min_severity: str = "info", triage: dict[str, dict] | None = None,
                llm: dict | None = None) -> dict:
        """`triage` maps finding ids to the model's triage (gittrace.llm.triage);
        it sits next to each finding and never changes the rules' fields."""
        shown = self.at_least(min_severity)
        counts = self.analysis.counts()
        triage = triage or {}
        summary = {**self.summary(shown), "test_findings": len(self.test_findings)}
        if llm and llm.get("enabled"):
            summary["likely_harmless"] = sum(
                1 for f in shown if (triage.get(f.id) or {}).get("verdict") == "likely_harmless")
        return {
            "project": self.project,
            "graph": self.graph,
            "settings": {"depth": self.depth, "min_severity": min_severity},
            "scanned": {k: counts[k] for k in ("files", "parse_failures", "functions", "endpoints", "calls")},
            "parse_failures": [{"file": f.path, "reason": f.reason} for f in self.analysis.failures],
            "llm": llm or {"enabled": False},
            "summary": summary,
            "findings": [{**f.to_dict(), "triage": triage.get(f.id)} for f in shown],
            "test_findings": [{**f.to_dict(), "triage": triage.get(f.id)} for f in self.test_findings],
        }


def is_test_path(path: str) -> bool:
    p = PurePosixPath(path)
    return (any(part in ("tests", "test") for part in p.parts[:-1])
            or p.name == "conftest.py" or p.name.startswith("test_") or p.stem.endswith("_test"))


def _exposure(match: Match, reach: Reach | None) -> Exposure:
    if reach is None:
        return Exposure()
    unauth = [r for r in reach.routes if not r.auth_required]
    auth = [r for r in reach.routes if r.auth_required]
    deciding = unauth or auth
    return Exposure(
        unauthenticated=len(unauth),
        authenticated=len(auth),
        callers=len(reach.callers),
        decided_by_unresolved_prefix=bool(deciding) and all(not r.prefix_resolved for r in deciding),
    )


def scan(root: str | os.PathLike, *, depth: int = DEFAULT_DEPTH, blame: bool = True,
         offline: bool = False, db=None, graph_name: str | None = None,
         include_tests: bool = False) -> ScanResult:
    check_depth(depth)
    analysis = pipeline.analyze(root)
    matches = run_rules(analysis.rules, analysis.calls, analysis.assignments)

    # A finding at module level in a file that makes no module-level calls
    # still needs its <module> node to hang from.
    present = {f.id for f in analysis.functions}
    for m in matches:
        if m.function_id not in present and m.function_id in analysis.module_scopes:
            analysis.functions.append(analysis.module_scopes[m.function_id])
            present.add(m.function_id)

    graph = name = None
    if offline:
        reachability = MemoryReachability(analysis, depth)
    else:
        from gittrace.graph import connection, store

        if db is None:
            db = connection.get_db()
        name = graph_name or store.graph_name_for(analysis.root)
        graph = db.select_graph(name)
        store.write_analysis(graph, analysis, name, sinks=matches)
        reachability = GraphReachability(graph, depth)

    owners: dict[tuple[str, int], Owner] = {}
    if blame and matches:
        blamer = Blamer(analysis.root)
        by_file: dict[str, list[int]] = {}
        for m in matches:
            by_file.setdefault(m.site.file, []).append(m.site.line)
        for file, lines in by_file.items():
            for line, owner in blamer.blame(file, lines).items():
                owners[(file, line)] = owner

    findings = []
    for m in matches:
        reach = reachability.reach(m.function_id) if m.flow_sensitive else None
        sev = score(m.base_severity, m.flow_sensitive, m.param_derived, _exposure(m, reach))
        in_tests = not include_tests and is_test_path(m.site.file)
        level, reasons = sev.level, sev.reasons
        if in_tests:
            level = "info"
            reasons += (f"in test code: reported at info instead of {sev.level} "
                        "(--include-tests to treat it normally)",)
        findings.append(Finding(
            id=m.sink_id, rule_id=m.rule_id, category=m.category, title=m.title,
            severity=level, score=sev.score, base_severity=m.base_severity,
            reasons=reasons, file=m.site.file, line=m.site.line, column=m.site.column,
            end_line=m.site.end_line, snippet=m.site.snippet, function_id=m.function_id,
            callee=m.callee, message=m.message, evidence=m.evidence,
            param_derived=m.param_derived, params=m.params, flow_sensitive=m.flow_sensitive,
            routes=reach.routes if reach else (), callers=reach.callers if reach else (),
            uncertain=sev.uncertain, owner=owners.get((m.site.file, m.site.line)),
            in_tests=in_tests,
        ))
    findings.sort(key=Finding.sort_key)

    if graph is not None:
        from gittrace.graph import store

        store.write_findings(graph, name, findings)
    return ScanResult(project=analysis.root.name, root=analysis.root, graph=name,
                      depth=depth, findings=[f for f in findings if not f.in_tests],
                      analysis=analysis, test_findings=[f for f in findings if f.in_tests])
