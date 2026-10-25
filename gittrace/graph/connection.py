"""
gittrace.graph.connection — the shared FalkorDB connection.

Graph code reaches the database through `connection.get_graph()` (attribute
access, not a from-import), so tests can swap in a mock graph in one place.

The installed falkordb 1.8.0 exposes:
    FalkorDB(host, port, username, password)   -> instance handle
        .connection      -> underlying redis.Redis
        .list_graphs()   -> [names]
        .select_graph(n) -> Graph
    Graph.query(cypher, params=None, timeout=None) -> QueryResult
    QueryResult.result_set  -> list of row-lists (primitives or Node/Edge objects)

There is no .ping(), no create_node_type / create_edge_type / create / create_edge /
match / get_graph / create_graph / drop_graph on either class.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

# gittrace/graph/connection.py -> the repository root, where .env lives.
load_dotenv(Path(__file__).resolve().parents[2] / ".env")


def _env(name: str, required: bool = True) -> str:
    value = os.environ.get(name, "").strip()
    if not value and required:
        raise RuntimeError(f"{name} is not set in .env")
    return value


FALKORDB_HOST = _env("FALKORDB_HOST")
FALKORDB_PORT = int(_env("FALKORDB_PORT", required=False) or "6379")
FALKORDB_USER = _env("FALKORDB_USER", required=False) or "default"
FALKORDB_PASSWORD = _env("FALKORDB_PASSWORD", required=False) or ""

# Overridable so the integration suite can seed an isolated graph instead of
# touching the demo graph on a shared instance.
GRAPH_NAME = _env("GITTRACE_GRAPH", required=False) or "gittrace"

_db = None


def get_db():
    """Lazily connect to FalkorDB and reuse the handle."""
    global _db
    if _db is not None:
        return _db

    try:
        from falkordb import FalkorDB
    except ImportError as exc:
        raise RuntimeError(
            "falkordb not installed. Run: pip install -r requirements.txt"
        ) from exc

    kwargs: dict = {"host": FALKORDB_HOST, "port": FALKORDB_PORT}
    # Credentials go together or not at all: redis-py sends AUTH whenever a
    # username is set, and AUTH with a username but no password fails to
    # encode, so an unauthenticated server (local Docker, CI) was unreachable.
    if FALKORDB_PASSWORD:
        kwargs["username"] = FALKORDB_USER
        kwargs["password"] = FALKORDB_PASSWORD

    _db = None
    try:
        _db = FalkorDB(**kwargs)
        # falkordb has no .ping(); the underlying redis client does.
        _db.connection.ping()
        return _db
    except Exception as first_err:  # noqa: BLE001
        # If the handle was created but the ping failed, discard it so a
        # later retry does not reuse a dead connection.
        _db = None
        raise RuntimeError(
            f"FalkorDB connect/ping failed for {kwargs.get('host')}:{kwargs.get('port')}: {first_err}"
        ) from first_err


def get_graph(db=None, name: str | None = None):
    """Get (or lazily create) the named graph handle.

    The default is read at call time, not bound at import, so tests can point
    every tool at a different graph by patching GRAPH_NAME.
    """
    if db is None:
        db = get_db()
    return db.select_graph(name or GRAPH_NAME)


def query(cypher: str, params: dict | None = None, name: str | None = None):
    """Run a Cypher query against the graph; return the QueryResult."""
    g = get_graph(None, name)
    return g.query(cypher, params=params)
