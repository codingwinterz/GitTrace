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
VERDICT_STYLE = {"likely_real": PINK, "uncertain": AMBER, "likely_harmless": TEAL}
SOURCE_STYLE = {"constant": TEAL, "internal": TEAL, "attacker": RED, "unknown": AMBER}
VERDICT_LABEL = {"likely_real": "likely real", "uncertain": "uncertain",
                 "likely_harmless": "likely harmless"}
_CONTEXT_LINES = 3
_MAX_ROUTES = 5
_WIDE_FINDINGS_WIDTH = 160

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
        text.append(owner["author"] or "unknown author")
        if owner.get("email"):                 # only with scan --show-email
            text.append(f" <{owner['email']}>")
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


def model_line(llm: dict | None) -> Text:
    if not llm or not llm.get("enabled"):
        return Text("model triage off (--no-llm): rule findings only", style=DIM)
    text = Text(f"model {llm['model']}: ", style=LAVENDER)
    for verdict, count in llm["by_verdict"].items():
        text.append(f"{count} {VERDICT_LABEL[verdict]}   ", style=VERDICT_STYLE[verdict] if count else DIM)
    extra = ([f"{llm['valid_fixes']} fix(es) that apply cleanly"] if llm.get("fixes") else []) +         [f"{llm['cached']} cached"]
    text.append(" · ".join(extra), style=DIM)
    if llm["errors"]:
        text.append(f" · {llm['errors']} could not be triaged", style=AMBER)
    if llm.get("recovered"):
        text.append(f" · {llm['recovered']} answered after the GPU ran out of memory", style=AMBER)
        if llm.get("reduced_context"):
            text.append(f" ({llm['reduced_context']} with a smaller context)", style=AMBER)
    return text


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
    model = model_line(data.get("llm"))
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
    return Panel(Group(grid, Text(), levels, reach, facts, model),
                 title=f"gittrace scan · {data['project']}",
                 border_style=RED if critical else AMBER)


def _adjusted(t: dict) -> Text:
    """The model's adjustment next to the rules' score: `-2 -> 9 critical`."""
    adj = t["severity_adjustment"]
    if adj == 0:
        return Text("±0", style=DIM)
    text = Text(f"{adj:+d} → {t['adjusted_score']} ", style=DIM)
    text.append(t["adjusted_severity"], style=SEVERITY_STYLE[t["adjusted_severity"]])
    return text


def verdict_text(t: dict | None) -> Text:
    if t is None:
        return Text("-", style=DIM)
    if t["error"]:
        return Text("error", style=AMBER)
    text = Text(VERDICT_LABEL[t["verdict"]], style=VERDICT_STYLE[t["verdict"]])
    if t["severity_adjustment"]:
        text.append(f" {t['severity_adjustment']:+d}", style=DIM)
    return text


def _finding_reach_and_auth(f: dict) -> tuple[Text, Text]:
    reach = f["reachability"]
    routes = reach["routes"]
    if not reach["applies"]:
        return Text("n/a (secret in source)", style=DIM), Text("n/a", style=DIM)
    if not routes:
        return Text("no endpoint", style=TEAL), Text("-", style=DIM)
    first = routes[0]
    reached = Text(f"{first['method']} {first['path']}", style=LAVENDER)
    if len(routes) > 1:
        reached.append(f" (+{len(routes) - 1})", style=DIM)
    if reach["uncertain"]:
        reached.append(" ?", style=AMBER)
    auth = Text("NO AUTH", style=RED) if reach["unauthenticated"] else Text("auth", style=AMBER)
    return reached, auth


def findings_table(findings: list[dict], start: int = 1,
                   compact: bool = False) -> Table:
    triaged = any(f.get("triage") for f in findings)
    table = Table(box=box.SIMPLE_HEAD, header_style="bold", expand=True)
    if compact:
        # Keep one readable cell per row; the scan renderer prints reasons as
        # separate wrapped text directly below each finding.
        table.add_column("Finding", overflow="fold", min_width=32, ratio=1)
        for i, f in enumerate(findings, start):
            table.add_row(_compact_finding_text(i, f, triaged))
        return table

    table.add_column("#", justify="right", style=DIM, no_wrap=True, min_width=1, width=3)
    table.add_column("Severity", no_wrap=True, min_width=8, width=8)
    table.add_column("Rule", no_wrap=True, min_width=11, width=11)
    table.add_column("Location", style=LAVENDER, overflow="fold", min_width=12, width=16)
    table.add_column("Reached from", overflow="fold", min_width=12, width=18)
    table.add_column("Auth", no_wrap=True, min_width=7, width=7)
    if triaged:
        table.add_column("Model", no_wrap=True, min_width=15, width=15)
    for i, f in enumerate(findings, start):
        reached, auth = _finding_reach_and_auth(f)
        loc = f"{f['location']['file']}:{f['location']['line']}"
        row = [str(i), severity_text(f["severity"]), f["rule_id"], loc, reached, auth]
        if triaged:
            row.append(verdict_text(f.get("triage")))
        table.add_row(*row)
    return table


def _compact_finding_text(index: int, f: dict, triaged: bool) -> Text:
    reached, auth = _finding_reach_and_auth(f)
    body = Text(f"{index}. ", style="bold")
    body.append_text(severity_text(f["severity"]))
    body.append(f" · {f['rule_id']}\n")
    body.append("   Location: ", style="bold")
    body.append(f"{f['location']['file']}:{f['location']['line']}", style=LAVENDER)
    body.append("\n   Reached from: ", style="bold")
    body.append_text(reached)
    body.append(" · ")
    body.append_text(auth)
    if triaged:
        body.append("\n   Model: ", style="bold")
        body.append_text(verdict_text(f.get("triage")))
    return body


def _render_findings_table(console: Console, findings: list[dict], start: int = 1,
                           reasons: bool = False) -> None:
    compact = console.width < _WIDE_FINDINGS_WIDTH or reasons
    if compact:
        triaged = any(f.get("triage") for f in findings)
        for index, finding in enumerate(findings, start):
            console.print(_compact_finding_text(index, finding, triaged))
            if reasons:
                triage = finding.get("triage") or {}
                reason = Text("   Model's reason: ", style="bold")
                reason.append(triage.get("reason") or triage.get("error") or "", style=DIM)
                console.print(reason, overflow="fold")
        return
    console.print(findings_table(findings, start=start))


def triage_parts(t: dict | None, f: dict) -> list:
    """The model's view of one finding, kept apart from the rules' facts."""
    if t is None:
        return []
    head = Text("model ", style="bold")
    head.append(t["model"] + (" (cached)" if t["cached"] else ""), style=LAVENDER)
    head.append(": ")
    if t["error"]:
        head.append("could not triage this finding: ", style=AMBER)
        head.append(t["error"], style=AMBER)
        return [head]
    head.append(VERDICT_LABEL[t["verdict"]].upper(), style=VERDICT_STYLE[t["verdict"]])
    head.append(f"  {t['reason']}")
    parts: list = [head]
    for note in t.get("call_notes") or ():
        parts.append(Text(f"model call: {note}", style=AMBER))
    # A secret is listed among the values with source "attacker" when the app
    # uses it (that is how the prompt's verdict rule works), but shown as an
    # "attacker input" it misleads: it is a constant in the user's own code.
    if t.get("values") and not f["rule_id"].startswith("GT-SECRET-"):
        inputs = Text("inputs, as the model sees them: ", style="bold")
        for i, v in enumerate(t["values"]):
            if i:
                inputs.append("  ·  ", style=DIM)
            inputs.append(v["value"], style=LAVENDER)
            inputs.append(f" {v['source']}", style=SOURCE_STYLE[v["source"]])
        parts.append(inputs)
    sev = Text("severity: rules ", style="bold")
    sev.append(f"{t['rules_score']} ")
    sev.append(f["severity"], style=SEVERITY_STYLE[f["severity"]])
    sev.append("  ·  model adjustment ", style="bold")
    sev.append_text(_adjusted(t))
    parts.append(sev)
    fix = t["fix"]
    if fix is None:                         # not asked for (scan without --fix)
        return parts
    if fix["valid"]:
        parts.append(Text("suggested fix (applies cleanly with git apply --check; not verified "
                          "correct; never applied):", style=TEAL))
        parts.append(Syntax(fix["diff"].rstrip("\n"), "diff", theme="ansi_dark",
                            background_color="default", word_wrap=True))
    else:
        parts.append(Text(f"no valid fix suggested ({fix['problem']})", style=DIM))
    return parts


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
    parts.extend(triage_parts(f.get("triage"), f))
    title = Text(f"{index}. ")
    title.append(f["severity"].upper(), style=SEVERITY_STYLE[f["severity"]])
    title.append(f"  {f['rule_id']}  {f['title']}  ")
    title.append(f"{loc['file']}:{loc['line']}:{loc['column']}", style=LAVENDER)
    return Panel(Group(*parts), title=title, title_align="left",
                 border_style=SEVERITY_STYLE[f["severity"]].replace("bold ", ""))


def _harmless(f: dict) -> bool:
    return (f.get("triage") or {}).get("verdict") == "likely_harmless"


def render_scan(console: Console, data: dict, functions: dict, blamed: bool) -> None:
    console.print(headline(data))
    findings = [f for f in data["findings"] if not _harmless(f)]
    harmless = [f for f in data["findings"] if _harmless(f)]
    if findings:
        _render_findings_table(console, findings)
        for i, f in enumerate(findings, 1):
            console.print(finding_detail(i, f, functions, blamed))
    if harmless:
        start = len(findings) + 1
        console.print(Text(
            f"Likely harmless according to the model: {len(harmless)} finding(s). The rules "
            "still report them at the severity shown, and --fail-on still counts them; "
            "check the model's reason.", style=LAVENDER))
        _render_findings_table(console, harmless, start=start, reasons=True)
        for i, f in enumerate(harmless, start):
            console.print(finding_detail(i, f, functions, blamed))
    tests = data.get("test_findings") or []
    if tests:
        console.print(Text(f"In test code: {len(tests)} finding(s), reported at info "
                           "(--include-tests to treat them normally)", style=LAVENDER))
        _render_findings_table(console, tests)
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
