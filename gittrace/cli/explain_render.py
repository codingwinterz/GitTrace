"""
gittrace.cli.explain_render — `gittrace explain` output: one data dict
(also the --format json output), drawn as Rich or written as Markdown.
"""

from __future__ import annotations

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from gittrace.cli.render import AMBER, DIM, LAVENDER, RED, SEVERITY_STYLE, TEAL
from gittrace.core.explain import Flow, ProjectExplanation, flows
from gittrace.languages.base import EFFECT_KINDS

FUNCTION_FIELDS = (("summary", "What it does"), ("inputs", "Inputs"), ("outputs", "Outputs"),
                   ("side_effects", "Side effects"), ("role", "Role in the app"))


# -- data ---------------------------------------------------------------------

def build_data(ex: ProjectExplanation, run, *, files: list[str], functions: list[str] | None,
               project: bool, settings: dict) -> dict:
    """Everything `explain` shows. `files`: the files to show; `functions`:
    restrict the functions shown (--function), else every function of those files."""
    def summary(level: str, target: str):
        s = run.get(level, target) if run is not None else None
        return s.to_dict() if s is not None else None

    shown_fns = set(functions) if functions is not None else None
    file_items = []
    for path in files:
        fi = ex.files[path]
        fns = []
        for fid in fi.functions:
            if shown_fns is not None and fid not in shown_fns:
                continue
            fns.append({**ex.functions[fid].to_dict(), "summary": summary("function", fid)})
        file_items.append({**fi.to_dict(), "summary": summary("file", path), "functions": fns})

    flow_items = []
    if project:
        flow_items = [f.to_dict() for f in flows(ex)]
    elif functions:
        for fl in flows(ex):
            if fl.root.function_id in functions:
                flow_items.append(fl.to_dict())
    removed = []
    if run is not None:
        for s in run.summaries.values():
            removed += [{"level": s.level, "target": s.target, "mention": m, "reason": r}
                        for m, r in s.grounding.removed]
    return {
        "project": ex.project,
        "scope": settings.get("scope"),
        "settings": {k: v for k, v in settings.items() if k != "scope"},
        "llm": run.meta() if run is not None else {"enabled": False},
        "overview": ex.to_dict() if project else None,
        "project_summary": summary("project", ex.project) if project else None,
        "flows": flow_items,
        "files": file_items,
        "grounding_removed": removed,
        "counts": {"files": len(ex.files), "functions": len(ex.summarisable()),
                   "important_functions": len(ex.important()), "endpoints": len(ex.endpoints)},
    }


# -- shared bits ----------------------------------------------------------------

def _auth(e: dict) -> str:
    return "auth" if e["auth_required"] else "NO AUTH"


def _effects(kinds) -> str:
    return ", ".join(EFFECT_KINDS[k] for k in kinds)


def _llm_line(llm: dict) -> str:
    if not llm.get("enabled"):
        return "model summaries off (--no-llm): facts only"
    g = llm["grounding"]
    minutes, seconds = divmod(int(llm["seconds"]), 60)
    return (f"model {llm['model']}: {llm['calls']} summaries ({llm['cached']} cached, {llm['errors']} errors) "
            f"in {minutes}m {seconds:02d}s; grounding check: {g['mentions_kept']} function mentions verified, "
            f"{g['removed']} removed")


# -- rich -----------------------------------------------------------------------

def _summary_block(s: dict | None, fields) -> list:
    if s is None:
        return []
    if s["error"]:
        return [Text(f"model summary unavailable: {s['error']}", style=AMBER)]
    out: list = []
    for key, label in fields:
        if key in s["text"]:
            line = Text(f"{label}: ", style="bold")
            line.append(s["text"][key])
            out.append(line)
    if s.get("terms"):
        out.append(Text("Terms used:", style="bold"))
        for t in s["terms"]:
            line = Text(f"  {t['term']}: ", style=LAVENDER)
            line.append(t["definition"], style=DIM)
            out.append(line)
    for m in s["grounding"]["removed"]:
        out.append(Text(f"removed unverified mention `{m['mention']}`: {m['reason']}", style=AMBER))
    for note in s["call_notes"]:
        out.append(Text(f"model call: {note}", style=AMBER))
    if s["context_notes"]:
        out.append(Text("context cut to fit: " + "; ".join(s["context_notes"]), style=DIM))
    return out


def _findings_block(findings: list[dict]) -> list:
    out = []
    for f in findings:
        line = Text("security: ", style="bold")
        line.append(f["severity"].upper(), style=SEVERITY_STYLE[f["severity"]])
        line.append(f" {f['title']} ({f['rule_id']}) at line {f['line']}")
        if f["in_tests"]:
            line.append(" (test code)", style=DIM)
        out.append(line)
    return out


def _flow_tree(tree: Tree, node: dict) -> None:
    label = Text(node["function"].split("::", 1)[1], style=LAVENDER)
    label.append(f"  {node['function'].split('::', 1)[0]}", style=DIM)
    if node["side_effects"]:
        label.append(f"  {_effects(node['side_effects'])}", style=AMBER)
    if node["note"]:
        label.append(f"  ({node['note']})", style=DIM)
    branch = tree.add(label)
    if node["library_calls"]:
        branch.add(Text("library: " + ", ".join(node["library_calls"]), style=DIM))
    for child in node["calls"]:
        _flow_tree(branch, child)


def render_rich(console: Console, data: dict) -> None:
    counts = data["counts"]
    head = Text(f"{counts['files']} files · {counts['functions']} functions "
                f"({counts['important_functions']} important) · {counts['endpoints']} endpoints", style=LAVENDER)
    scope = data["scope"]
    title = f"GitTrace explain · {data['project']}" + (f" · {scope}" if scope else "")
    console.print(Panel(Group(head, Text(_llm_line(data["llm"]), style=DIM)), title=title, border_style=LAVENDER))

    ps = data["project_summary"]
    if ps is not None:
        console.print(Panel(Group(*_summary_block(ps, (("summary", "What it is"),
                                                       ("how_it_works", "How it works")))),
                            title="The project in plain language", border_style=TEAL))

    ov = data["overview"]
    if ov is not None:
        t = Table(title="Entry points (where the program starts)", box=box.SIMPLE_HEAD, expand=True)
        t.add_column("Kind", style=LAVENDER, no_wrap=True)
        t.add_column("Where", overflow="fold")
        t.add_column("What", overflow="fold")
        for e in ov["entry_points"]:
            t.add_row(e["kind"], f"{e['file']}:{e['line']}", e["detail"])
        if not ov["entry_points"]:
            t.add_row("-", "-", "none found")
        console.print(t)

        t = Table(title="Endpoints (URLs the app answers)", box=box.SIMPLE_HEAD, expand=True)
        for col in ("Method", "Path", "Auth", "Handler"):
            t.add_column(col, overflow="fold", no_wrap=col in ("Method", "Auth"))
        for e in ov["endpoints"]:
            path = Text(e["path"])
            if not e["prefix_resolved"]:
                path.append("  (prefix not resolved)", style=AMBER)
            t.add_row(e["method"], path, Text(_auth(e), style=RED if not e["auth_required"] else TEAL),
                      Text(e["handler"], style=LAVENDER))
        if not ov["endpoints"]:
            t.add_row("-", "none found", "", "")
        console.print(t)

        tree = Tree(Text("Modules by folder", style="bold"))
        files = {f["path"]: f for f in data["files"]}
        for folder, paths in ov["modules"].items():
            branch = tree.add(Text(folder + "/", style=LAVENDER))
            for p in paths:
                f = files.get(p)
                desc = ""
                if f is not None and f["summary"] and f["summary"]["text"]:
                    desc = f["summary"]["text"]["summary"].split(". ")[0].rstrip(".") + "."
                elif f is not None and f["doc"]:
                    desc = f["doc"]
                label = Text(p.rsplit("/", 1)[-1])
                if desc:
                    label.append(f"  {desc}", style=DIM)
                branch.add(label)
        console.print(tree)

        libs = ", ".join(f"{name} ({len(fs)} file{'s' if len(fs) != 1 else ''})"
                         for name, fs in ov["libraries"].items())
        console.print(Text("Third-party libraries: ", style="bold") + Text(libs or "none"))
        t = Table(title="Data stores and outside services", box=box.SIMPLE_HEAD, expand=True)
        for col in ("Service", "What it means", "Evidence"):
            t.add_column(col, overflow="fold")
        for s in ov["services"]:
            t.add_row(Text(s["name"], style=LAVENDER), s["explanation"], s["evidence"][0] if s["evidence"] else "")
        if not ov["services"]:
            t.add_row("-", "none found", "")
        console.print(t)
        if ov["parse_failures"]:
            console.print(Text(f"{len(ov['parse_failures'])} file(s) could not be parsed and are left out: "
                               + ", ".join(f["file"] for f in ov["parse_failures"]), style=AMBER))

    if data["flows"]:
        tree = Tree(Text("How requests flow (handler → project functions it calls)", style="bold"))
        for fl in data["flows"]:
            eps = ", ".join(f"{e['method']} {e['path']}" for e in fl["endpoints"])
            unauth = any(not e["auth_required"] for e in fl["endpoints"])
            top = tree.add(Text(eps, style="bold") + Text(f"  [{'NO AUTH' if unauth else 'auth'}]",
                                                           style=RED if unauth else TEAL))
            _flow_tree(top, fl["tree"])
        console.print(tree)

    for f in data["files"]:
        parts: list = []
        if f["summary"] is not None:
            parts += _summary_block(f["summary"], (("summary", "What it is"), ("role", "Role in the app")))
        elif f["doc"]:
            parts.append(Text(f"Docstring: {f['doc']}"))
        facts = []
        if f["imports"]["external"]:
            facts.append("libraries: " + ", ".join(f["imports"]["external"]))
        if f["side_effects"]:
            facts.append("side effects: " + _effects(k for k in EFFECT_KINDS if k in f["side_effects"]))
        if facts:
            parts.append(Text(" · ".join(facts), style=DIM))
        parts += _findings_block(f["findings"])
        for fn in f["functions"]:
            head = Text(fn["qualified_name"], style=LAVENDER)
            head.append(f"  lines {fn['lines'][0]}-{fn['lines'][1]}", style=DIM)
            for h in fn["handles"]:
                head.append(f"  {h['method']} {h['path']}", style="bold")
            if fn["side_effects"]:
                head.append("  " + _effects(sorted({e['kind'] for e in fn['side_effects']},
                                                    key=list(EFFECT_KINDS).index)), style=AMBER)
            parts.append(head)
            block = _summary_block(fn["summary"], FUNCTION_FIELDS)
            if block:
                parts += [Text("    ") + b if isinstance(b, Text) else b for b in block]
            elif fn["doc"]:
                parts.append(Text(f"    {fn['doc']}", style=DIM))
            parts += [Text("    ") + b for b in _findings_block(fn["findings"])]
        console.print(Panel(Group(*parts) if parts else Text("(empty file)", style=DIM),
                            title=f["path"], title_align="left", border_style=LAVENDER))

    removed = data["grounding_removed"]
    if removed:
        console.print(Text(f"Grounding check: {len(removed)} unverified function mention(s) removed "
                           "from the summaries (shown next to each summary).", style=AMBER))


# -- markdown ---------------------------------------------------------------------

def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _md_summary(s: dict | None, fields, indent: str = "") -> list[str]:
    if s is None:
        return []
    if s["error"]:
        return [f"{indent}*Model summary unavailable: {s['error']}*", ""]
    out = []
    for key, label in fields:
        if key in s["text"]:
            out.append(f"{indent}- **{label}:** {s['text'][key]}")
    if s.get("terms"):
        out.append(f"{indent}- **Terms used:**")
        out += [f"{indent}  - *{t['term']}*: {t['definition']}" for t in s["terms"]]
    for m in s["grounding"]["removed"]:
        out.append(f"{indent}- *Removed unverified mention `{m['mention']}`: {m['reason']}.*")
    for note in s["call_notes"]:
        out.append(f"{indent}- *Model call: {note}.*")
    if s["context_notes"]:
        out.append(f"{indent}- *Context cut to fit: {'; '.join(s['context_notes'])}.*")
    return out + [""]


def _md_flow(node: dict, depth: int) -> list[str]:
    line = f"{'  ' * depth}- `{node['function']}`"
    if node["side_effects"]:
        line += f": {_effects(node['side_effects'])}"
    if node["note"]:
        line += f" ({node['note']})"
    out = [line]
    if node["library_calls"]:
        out.append(f"{'  ' * (depth + 1)}- library: {', '.join(node['library_calls'])}")
    for c in node["calls"]:
        out += _md_flow(c, depth + 1)
    return out


def to_markdown(data: dict) -> str:
    out = [f"# {data['project']}: how the code works", ""]
    c = data["counts"]
    out += [f"Generated by `gittrace explain`. {c['files']} files, {c['functions']} functions "
            f"({c['important_functions']} important), {c['endpoints']} endpoints. {_llm_line(data['llm'])}.",
            "", "Facts (entry points, endpoints, calls, side effects, findings) come from GitTrace's analysis "
            "of the code. Summaries come from a language model and can be wrong; function mentions in them "
            "were checked against the call graph. The \"Terms used\" under a summary are GitTrace's own "
            "definitions of the technical terms it uses, not the model's.", ""]
    if data["scope"]:
        out += [f"Scope: {data['scope']}.", ""]
    ps = data["project_summary"]
    if ps is not None:
        out += ["## The project in plain language", ""]
        out += _md_summary(ps, (("summary", "What it is"), ("how_it_works", "How it works")))
    ov = data["overview"]
    if ov is not None:
        out += ["## Entry points", "", "Where the program starts.", ""]
        if ov["entry_points"]:
            out += ["| Kind | Where | What |", "|---|---|---|"]
            out += [f"| {e['kind']} | `{e['file']}:{e['line']}` | {_md_escape(e['detail'])} |"
                    for e in ov["entry_points"]]
        else:
            out.append("None found.")
        out += ["", "## Endpoints", "", "URLs the app answers, and the function that handles each.", ""]
        if ov["endpoints"]:
            out += ["| Method | Path | Auth | Handler |", "|---|---|---|---|"]
            for e in ov["endpoints"]:
                path = e["path"] + (" (prefix not resolved)" if not e["prefix_resolved"] else "")
                out.append(f"| {e['method']} | `{_md_escape(path)}` | {_auth(e)} | `{e['handler']}` |")
        else:
            out.append("None found.")
        out += ["", "## Modules by folder", ""]
        files = {f["path"]: f for f in data["files"]}
        for folder, paths in ov["modules"].items():
            out.append(f"- `{folder}/`")
            for p in paths:
                f = files.get(p)
                desc = ""
                if f is not None and f["summary"] and f["summary"]["text"]:
                    desc = f["summary"]["text"]["summary"].split(". ")[0].rstrip(".") + "."
                elif f is not None and f["doc"]:
                    desc = f["doc"]
                out.append(f"  - `{p.rsplit('/', 1)[-1]}`" + (f": {desc}" if desc else ""))
        out += ["", "## Libraries, data stores and services", ""]
        libs = ", ".join(f"`{n}` ({len(fs)})" for n, fs in ov["libraries"].items())
        out += [f"Third-party libraries (files importing them): {libs or 'none'}.", ""]
        for s in ov["services"]:
            out.append(f"- **{s['name']}**: {s['explanation']} (e.g. `{s['evidence'][0]}`)" if s["evidence"]
                       else f"- **{s['name']}**: {s['explanation']}")
        if not ov["services"]:
            out.append("None found.")
        out.append("")
    if data["flows"]:
        out += ["## How requests flow", "",
                "For each endpoint: the handler and the project functions it calls, with library calls "
                "collapsed onto one line.", ""]
        for fl in data["flows"]:
            eps = ", ".join(f"`{e['method']} {e['path']}` ({_auth(e)})" for e in fl["endpoints"])
            out += [f"**{eps}**", ""] + _md_flow(fl["tree"], 0) + [""]
    if data["files"]:
        out += ["## Files", ""]
    for f in data["files"]:
        out += [f"### `{f['path']}`", ""]
        if f["summary"] is not None:
            out += _md_summary(f["summary"], (("summary", "What it is"), ("role", "Role in the app")))
        elif f["doc"]:
            out += [f"Docstring: {f['doc']}", ""]
        for x in f["findings"]:
            out.append(f"- Security: **{x['severity']}** {x['title']} (`{x['rule_id']}`) at line {x['line']}"
                       + (" (test code)" if x["in_tests"] else ""))
        if f["findings"]:
            out.append("")
        for fn in f["functions"]:
            handles = "".join(f" `{h['method']} {h['path']}`" for h in fn["handles"])
            effects = sorted({e["kind"] for e in fn["side_effects"]}, key=list(EFFECT_KINDS).index)
            out.append(f"#### `{fn['qualified_name']}` (lines {fn['lines'][0]}-{fn['lines'][1]}){handles}")
            out.append("")
            if effects:
                out += [f"Side effects found: {_effects(effects)}.", ""]
            block = _md_summary(fn["summary"], FUNCTION_FIELDS)
            if block:
                out += block
            elif fn["doc"]:
                out += [fn["doc"], ""]
            for x in fn["findings"]:
                out.append(f"- Security: **{x['severity']}** {x['title']} (`{x['rule_id']}`) at line {x['line']}")
            if fn["findings"]:
                out.append("")
    if data["grounding_removed"]:
        out += ["## Grounding check", "",
                f"{len(data['grounding_removed'])} function mention(s) were removed from the summaries because "
                "the call graph does not connect them to the code being described:", ""]
        out += [f"- {r['level']} `{r['target']}`: `{r['mention']}` ({r['reason']})" for r in data["grounding_removed"]]
        out.append("")
    return "\n".join(out).rstrip() + "\n"


__all__ = ["Flow", "build_data", "render_rich", "to_markdown"]
