"""
gittrace.ingest — temporary entry point: scan a project into its FalkorDB graph
and print what was found. `gittrace scan` (Phase 4) replaces it.

    python -m gittrace.ingest <path>            # scan and write the graph
    python -m gittrace.ingest <path> --dry-run  # parse and resolve only, no database
"""

from __future__ import annotations

import argparse
import logging
import sys

from gittrace.core import pipeline


def _report(counts: dict[str, int], failures) -> str:
    calls = counts["calls"]
    resolved = counts["resolved_calls"]
    pct = f" ({resolved / calls:.0%})" if calls else ""
    lines = [
        f"files:            {counts['files']}",
        f"parse failures:   {counts['parse_failures']}",
        f"functions:        {counts['functions']} (+{counts['module_scopes']} module scopes)",
        f"endpoints:        {counts['endpoints']}",
        f"calls:            {calls}",
        f"  resolved:       {resolved}{pct}",
        f"  unresolved:     {counts['unresolved_calls']}"
        f" (builtin {counts['unresolved_builtin']}, import {counts['unresolved_import']},"
        f" project {counts['unresolved_project']}, unknown {counts['unresolved_unknown']})",
        f"  class, no init: {counts['class_instantiations']}",
        f"external callees: {counts['external_callees']}",
    ]
    lines += [f"  failed: {f.path}: {f.reason}" for f in failures]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m gittrace.ingest", description=__doc__.split("\n\n")[0])
    parser.add_argument("path", help="project folder to scan")
    parser.add_argument("--dry-run", action="store_true", help="do not write to FalkorDB")
    parser.add_argument("--graph", help="graph name (default: derived from the path)")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

    try:
        if args.dry_run:
            analysis, graph = pipeline.analyze(args.path), None
        else:
            analysis, graph = pipeline.ingest(args.path, graph_name=args.graph)
    except (NotADirectoryError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"project: {analysis.root}")
    print(f"graph:   {graph or '(dry run, nothing written)'}")
    print(_report(analysis.counts(), analysis.failures))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
