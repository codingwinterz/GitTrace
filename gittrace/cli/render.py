"""
gittrace.cli.render — Rich output for the CLI.

Colours follow CLAUDE.md: red/pink = critical, amber = warning, teal = clean,
lavender = structural information (paths, trees, ids).
"""

from __future__ import annotations

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

RED = "bold red"
PINK = "bold #ff5f87"
AMBER = "#ffaf00"
AMBER_DIM = "#d7af5f"
TEAL = "#00afaf"
LAVENDER = "#af87ff"
DIM = "grey62"

SEVERITY_STYLE = {
    "critical": RED, "high": PINK, "medium": AMBER, "low": AMBER_DIM, "info": DIM,
}
_CONTEXT_LINES = 3
_MAX_ROUTES = 5

# A 5-row block font for the headline numbers: Rich cannot change font size.
_DIGITS = {
    "0": ["███", "█ █", "█ █", "█ █", "███"], "1": [" █ ", "██ ", " █ ", " █ ", "███"],
    "2": ["███", "  █", "███", "█  ", "███"], "3": ["███", "  █", "███", "  █", "███"],
    "4": ["█ █", "█ █", "███", "  █", "  █"], "5": ["███", "█  ", "███", "  █", "███"],
    "6": ["███", "█  ", "███", "█ █", "███"], "7": ["███", "  █", "  █", "  █", "  █"],
    "8": ["███", "█ █", "███", "█ █", "███"], "9": ["███", "█ █", "███", "  █", "███"],
}


def big_number(value: int, style: str) -> Text:
    rows = ["  ".join(_DIGITS[d][r] for d in str(value)) for r in range(5)]
    return Text("\n".join(rows), style=style)


def severity_text(level: str) -> Text:
    return Text(level.upper(), style=SEVERITY_STYLE[level])


def _route_label(route: dict) -> Text:
    label = Text(f"{route['method']} {route['path']}", style=LAVENDER)
    if route["auth_required"]:
        label.append("  authenticated", style=AMBER)
    else:
        label.append("  NO AUTH", style=RED)
    if not route["prefix_resolved"]:
        label.append("  (prefix not fully resolved)", style=AMBER_DIM)
    return label


def path_tree(title: str, routes: list[dict], sink_label: Text | None = None) -> Tree:
    tree = Tree(Text(title, style="bold"), guide_style=LAVENDER)
    for route in routes[:_MAX_ROUTES]:
        node = tree.add(_route_label(route))
        for step in route["path_nodes"][1:]:
            node = node.add(Text(step, style=LAVENDER))
        if sink_label is not None:
            node.add(sink_label)
    if len(routes) > _MAX_ROUTES:
        tree.add(Text(f"... {len(routes) - _MAX_ROUTES} more route(s)", style=DIM))
    if not routes:
        tree.add(Text("no endpoint reaches this code", style=TEAL))
    return tree


def _owner_line(owner: dict | None, blamed: bool) -> Text:
    text = Text("owner: ", style="bold")
    if owner is None:
        text.append("unknown" + ("" if blamed else " (owner lookup skipped)"), style=DIM)
    elif owner["status"] == "uncommitted":
        text.append("line not committed yet", style=DIM)
    else:
        text.append(f"{owner['author']} <{owner['email']}>")
        text.append(f"  {owner['commit'][:10]}  {(owner['date'] or '')[:10]}", style=LAVENDER)
        if owner.get("summary"):
            text.append(f"  {owner['summary']}", style=DIM)
    return text


def _snippet(finding: dict, functions: dict) -> Syntax:
    line = finding["location"]["line"]
    fn = functions.get(finding["function"])
    if fn is not None and finding["category"] != "hardcoded-secret":   # its snippet is masked
        lines = fn.source.splitlines()
        first = max(fn.start_line, line - _CONTEXT_LINES)
        last = min(fn.end_line, finding["location"]["end_line"] + _CONTEXT_LINES)
        code = "\n".join(lines[first - fn.start_line:last - fn.start_line + 1])
    else:
        first, code = line, finding["snippet"]
    return Syntax(code, "python", line_numbers=True, start_line=first,
                  highlight_lines={line}, theme="ansi_dark", background_color="default",
                  word_wrap=True)


def headline(data: dict) -> Panel:
    summary = data["summary"]
    total, critical = summary["total"], summary["by_severity"]["critical"]
    scanned = data["scanned"]
    facts = Text(
        f"{scanned['files']} files · {scanned['functions']} functions · "
        f"{scanned['endpoints']} endpoints scanned"
        + (f" · {scanned['parse_failures']} could not be parsed" if scanned["parse_failures"] else "")
        + (f" · {summary['test_findings']} more in test code (info)" if summary.get("test_findings") else ""),
        style=LAVENDER,
    )
    if total == 0:
        return Panel(Group(Text("NO FINDINGS", style=f"bold {TEAL}"), facts),
                     title=f"gittrace scan · {data['project']}", border_style=TEAL)
    grid = Table.grid(padding=(0, 6))
    grid.add_row(big_number(total, "bold"), big_number(critical, RED if critical else TEAL))
    grid.add_row(Text("FINDINGS", style="bold"), Text("CRITICAL", style=RED if critical else TEAL))
    levels = Text()
    for level, count in summary["by_severity"].items():
        levels.append(f"{count} {level}   ", style=SEVERITY_STYLE[level] if count else DIM)
    reach = Text(
        f"{summary['reachable']} reachable from an endpoint · "
        f"{summary['unauthenticated']} from an unauthenticated endpoint",
        style=RED if summary["unauthenticated"] else AMBER,
    )
    return Panel(Group(grid, Text(), levels, reach, facts),
                 title=f"gittrace scan · {data['project']}",
                 border_style=RED if critical else AMBER)


def findings_table(findings: list[dict]) -> Table:
    table = Table(box=box.SIMPLE_HEAD, header_style="bold", expand=True)
    table.add_column("#", justify="right", style=DIM, no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Rule", no_wrap=True)
    table.add_column("Location", style=LAVENDER, overflow="fold")
    table.add_column("Reached from", overflow="fold")
    table.add_column("Auth", no_wrap=True)
    for i, f in enumerate(findings, 1):
        reach = f["reachability"]
        routes = reach["routes"]
        if not reach["applies"]:
            reached, auth = Text("n/a (secret in source)", style=DIM), Text("n/a", style=DIM)
        elif not routes:
            reached, auth = Text("no endpoint", style=TEAL), Text("-", style=DIM)
        else:
            first = routes[0]
            reached = Text(f"{first['method']} {first['path']}", style=LAVENDER)
            if len(routes) > 1:
                reached.append(f" (+{len(routes) - 1})", style=DIM)
            if reach["uncertain"]:
                reached.append(" ?", style=AMBER)
            auth = Text("NO AUTH", style=RED) if reach["unauthenticated"] else Text("auth", style=AMBER)
        loc = f"{f['location']['file']}:{f['location']['line']}"
        table.add_row(str(i), severity_text(f["severity"]), f["rule_id"], loc, reached, auth)
    return table


def finding_detail(index: int, f: dict, functions: dict, blamed: bool) -> Panel:
    loc = f["location"]
    sink = Text(f"{f['callee'] or 'assignment'}  at {loc['file']}:{loc['line']}", style=RED)
    parts = [Text(f["message"]), Text(" · ".join(f["evidence"]), style=DIM), _snippet(f, functions)]
    reach = f["reachability"]
    if reach["applies"]:
        parts.append(path_tree("Attack paths (unauthenticated first)", reach["routes"], sink))
        br = f["blast_radius"]
        parts.append(Text(
            f"blast radius: {br['total']}  ({len(br['callers'])} upstream caller(s), "
            f"{br['endpoints']} endpoint(s))", style="bold"))
        if reach["uncertain"]:
            parts.append(Text("uncertain: every deciding route has an unresolved prefix", style=AMBER))
    parts.append(_owner_line(f["owner"], blamed))
    parts.append(Text("severity: " + "; ".join(f["reasons"]), style=DIM))
    title = Text(f"{index}. ")
    title.append(f["severity"].upper(), style=SEVERITY_STYLE[f["severity"]])
    title.append(f"  {f['rule_id']}  {f['title']}  ")
    title.append(f"{loc['file']}:{loc['line']}:{loc['column']}", style=LAVENDER)
    return Panel(Group(*parts), title=title, title_align="left",
                 border_style=SEVERITY_STYLE[f["severity"]].replace("bold ", ""))


def render_scan(console: Console, data: dict, functions: dict, blamed: bool) -> None:
    console.print(headline(data))
    findings = data["findings"]
    if findings:
        console.print(findings_table(findings))
        for i, f in enumerate(findings, 1):
            console.print(finding_detail(i, f, functions, blamed))
    tests = data.get("test_findings") or []
    if tests:
        console.print(Text(f"In test code: {len(tests)} finding(s), reported at info "
                           "(--include-tests to treat them normally)", style=LAVENDER))
        console.print(findings_table(tests))
    if data["parse_failures"]:
        console.print(Text("Not scanned (parse failures):", style=AMBER))
        for failure in data["parse_failures"]:
            console.print(Text(f"  {failure['file']}: {failure['reason']}", style=AMBER_DIM))


def render_trace(console: Console, data: dict) -> None:
    for trace in data["traces"]:
        f = trace["finding"]
        header = Text()
        header.append((f["severity"] or "?").upper(), style=SEVERITY_STYLE.get(f["severity"], DIM))
        header.append(f"  {f['rule_id']}  {f['file']}:{f['line']}:{f['column']}  ")
        header.append(f["function"], style=LAVENDER)
        sink = Text(f"{f['callee'] or 'assignment'}  at {f['file']}:{f['line']}", style=RED)
        console.print(Panel(
            Group(Text(f["message"]), Text(f["snippet"], style=DIM),
                  path_tree(f"Attack paths (depth {data['depth']}, unauthenticated first)",
                            trace["routes"], sink),
                  Text(f"{len(trace['callers'])} upstream caller(s)", style=LAVENDER)),
            title=header, title_align="left", border_style=LAVENDER))


def render_blast_radius(console: Console, data: dict) -> None:
    head = Table.grid(padding=(0, 6))
    head.add_row(big_number(data["total"], "bold"),
                 big_number(data["unauthenticated_endpoints"],
                            RED if data["unauthenticated_endpoints"] else TEAL))
    head.add_row(Text("BLAST RADIUS", style="bold"),
                 Text("UNAUTHENTICATED ENDPOINTS",
                      style=RED if data["unauthenticated_endpoints"] else TEAL))
    callers = Tree(Text(f"{data['caller_count']} upstream caller(s)", style="bold"), guide_style=LAVENDER)
    for c in data["callers"]:
        callers.add(Text(c, style=LAVENDER))
    sinks = Text("findings in this function: " + (", ".join(data["sinks"]) or "none"),
                 style=RED if data["sinks"] else TEAL)
    console.print(Panel(
        Group(head, Text(), Text(f"{data['function']}  {data['file']}:{data['start_line']}-{data['end_line']}",
                                 style=LAVENDER), sinks, callers,
              path_tree(f"{data['endpoint_count']} endpoint(s) (depth {data['depth']})", data["routes"])),
        title="gittrace blast-radius", title_align="left", border_style=LAVENDER))
