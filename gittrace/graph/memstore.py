"""
gittrace.graph.memstore — the project graph, held in memory (NetworkX).

One GraphStore per scanned project. Nodes are keyed by (label, key): each
label has its own key space, as each node label had in FalkorDB (a File's
`path`, otherwise the `id`). Every node pair carries at most one edge, and
each edge type joins its own pair of labels (DECLARES File->Function|Endpoint,
HANDLED_BY Endpoint->Function, CALLS Function->Function, REACHES_SINK
Function->Sink), so a DiGraph is enough; merge_edge refuses a second type.

Writes follow MERGE: a node's properties are updated in place, and an edge
is written only when both of its nodes exist.

The graph is cached in <project>/.gittrace/graph.json, written atomically,
with the sha256 of every source file discovery finds. A cache whose hashes
do not match the files on disk is never loaded. Function `source` is left
out of the cache (it can hold the project's hardcoded secrets; nothing reads
it back); Sink snippets are already masked.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path

import networkx as nx

CACHE_FILE = Path(".gittrace") / "graph.json"
FORMAT_VERSION = 1
NOT_CACHED = {"Function": ("source",)}
EDGE_LABELS = {
    "DECLARES": ("File", ("Function", "Endpoint")),
    "HANDLED_BY": ("Endpoint", ("Function",)),
    "CALLS": ("Function", ("Function",)),
    "REACHES_SINK": ("Function", ("Sink",)),
}


class StaleCache(Exception):
    """The cached graph does not match the files on disk (or there is none)."""


def file_hashes(root: str | os.PathLike) -> dict[str, str]:
    """sha256 of the raw bytes of every file a scan would read."""
    from gittrace.core.discover import discover
    from gittrace.languages import plugins

    root = Path(root)
    hashes: dict[str, str] = {}
    for plugin in plugins():
        for rel in discover(root, plugin.extensions):
            try:
                hashes[rel] = hashlib.sha256((root / rel).read_bytes()).hexdigest()
            except OSError:
                hashes[rel] = "unreadable"
    return hashes


class GraphStore:
    def __init__(self, name: str):
        self.name = name
        self.g = nx.DiGraph()

    # -- writes -------------------------------------------------------------

    def merge_node(self, label: str, key: str, props: dict) -> None:
        node = (label, key)
        if node in self.g:
            self.g.nodes[node]["props"].update(props)
        else:
            self.g.add_node(node, label=label, props=dict(props))

    def merge_edge(self, type_: str, a: tuple[str, str], b: tuple[str, str], props: dict | None = None) -> None:
        if a not in self.g or b not in self.g:
            return
        src, dst = EDGE_LABELS[type_]
        if a[0] != src or b[0] not in dst:
            raise ValueError(f"{type_} cannot join {a[0]} to {b[0]}")
        if self.g.has_edge(a, b) and self.g.edges[a, b]["type"] != type_:
            raise ValueError(f"{a} -> {b} already has a {self.g.edges[a, b]['type']} edge")
        self.g.add_edge(a, b, type=type_, props=dict(props or {}))

    # -- reads --------------------------------------------------------------

    def props(self, label: str, key: str) -> dict | None:
        node = (label, key)
        return self.g.nodes[node]["props"] if node in self.g else None

    def nodes(self, label: str) -> list[dict]:
        return [d["props"] for n, d in self.g.nodes(data=True) if n[0] == label]

    def sink(self, sink_id: str) -> dict | None:
        props = self.props("Sink", sink_id)
        return None if props is None else {"id": sink_id, **props}

    def sinks(self) -> list[dict]:
        return [{"id": n[1], **d["props"]} for n, d in self.g.nodes(data=True) if n[0] == "Sink"]

    def sinks_at(self, file: str, line: int) -> list[dict]:
        found = [s for s in self.sinks() if s.get("file") == file and s.get("line") == line]
        return sorted(found, key=lambda s: s.get("column") or 0)

    def function(self, function_id: str) -> tuple[dict, list[str]] | None:
        """A resolved function's properties and the ids of its Sinks."""
        props = self.props("Function", function_id)
        if props is None or props.get("resolved") is not True:
            return None
        node = ("Function", function_id)
        sinks = [b[1] for b in self.g.successors(node) if self.g.edges[node, b]["type"] == "REACHES_SINK"]
        return props, sinks

    def callers_of(self, function_id: str) -> list[str]:
        node = ("Function", function_id)
        if node not in self.g:
            return []
        return [a[1] for a in self.g.predecessors(node) if self.g.edges[a, node]["type"] == "CALLS"]

    def callees_of(self, function_id: str) -> list[str]:
        node = ("Function", function_id)
        if node not in self.g:
            return []
        return [b[1] for b in self.g.successors(node) if self.g.edges[node, b]["type"] == "CALLS"]

    def endpoints_handled_by(self, function_id: str) -> list[dict]:
        node = ("Function", function_id)
        if node not in self.g:
            return []
        return [{"id": a[1], **self.g.nodes[a]["props"]} for a in self.g.predecessors(node)
                if self.g.edges[a, node]["type"] == "HANDLED_BY"]

    # -- cache --------------------------------------------------------------

    def to_dict(self, hashes: dict[str, str]) -> dict:
        from gittrace import __version__

        nodes = []
        for (label, key), data in self.g.nodes(data=True):
            props = {k: v for k, v in data["props"].items() if k not in NOT_CACHED.get(label, ())}
            nodes.append([label, key, props])
        edges = [[d["type"], list(a), list(b), d["props"]] for a, b, d in self.g.edges(data=True)]
        return {"format": FORMAT_VERSION, "gittrace": __version__, "graph": self.name,
                "files": hashes, "nodes": nodes, "edges": edges}

    def save(self, root: str | os.PathLike) -> Path:
        """Write the cache atomically: a temporary file in .gittrace/, then a rename."""
        base = Path(root) / ".gittrace"
        base.mkdir(parents=True, exist_ok=True)
        ignore = base / ".gitignore"
        if not ignore.exists():
            ignore.write_text("# created by gittrace: project graph cache\n*\n", encoding="utf-8")
        path = Path(root) / CACHE_FILE
        data = self.to_dict(file_hashes(root))
        fd, tmp = tempfile.mkstemp(dir=base, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return path

    @classmethod
    def load(cls, root: str | os.PathLike) -> GraphStore:
        """The cached graph of `root`. StaleCache when there is none, it cannot
        be read, or any source file was changed, added or removed since."""
        path = Path(root) / CACHE_FILE
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise StaleCache("no graph") from None
        except (OSError, ValueError) as exc:
            raise StaleCache(f"unreadable graph cache: {exc}") from None
        if not isinstance(data, dict) or data.get("format") != FORMAT_VERSION:
            raise StaleCache("graph cache from another GitTrace version")
        if data.get("files") != file_hashes(root):
            raise StaleCache("the project's files changed since the last scan")
        store = cls(data["graph"])
        for label, key, props in data["nodes"]:
            store.g.add_node((label, key), label=label, props=props)
        for type_, a, b, props in data["edges"]:
            store.g.add_edge(tuple(a), tuple(b), type=type_, props=props)
        return store
