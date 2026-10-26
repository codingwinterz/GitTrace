"""
gittrace.graph.connection — the shared FalkorDB connection.

Graph code reaches the database through `connection.get_db()` (attribute
access, not a from-import), so tests can swap in a mock in one place. Each
scanned project has its own graph; see gittrace.graph.store.graph_name_for.

Settings come from the environment or .env, defaulting to local Docker
(localhost:6379, no password). GitTrace only ever describes the database as
"local" or "remote" (location()); the host, port and password are redacted
from every message (redact()). Graph writes to a remote database need
--allow-remote (require_local_or_allowed()). check() is a real round trip
with a short timeout, for status displays.

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
import re

from gittrace import config

config.load()                           # .env, if any (gittrace.config); variables win


def _env(name: str) -> str:
    return os.environ.get(name, "").strip()


# Local Docker (`docker compose up -d falkordb`) unless .env or the
# environment says otherwise.
FALKORDB_HOST = _env("FALKORDB_HOST") or "localhost"
FALKORDB_PORT = int(_env("FALKORDB_PORT") or "6379")
FALKORDB_USER = _env("FALKORDB_USER") or "default"
FALKORDB_PASSWORD = _env("FALKORDB_PASSWORD")

LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
CONNECT_TIMEOUT_S = 10.0
CHECK_TIMEOUT_S = 3.0

_db = None


class RemoteNotAllowed(RuntimeError):
    """A graph write to a FalkorDB that is not on this machine, without --allow-remote."""


def is_local(host: str | None = None) -> bool:
    return (host if host is not None else FALKORDB_HOST).strip().lower() in LOCAL_HOSTS


def location() -> str:
    """'local' or 'remote': all GitTrace ever says about where the database is.
    The host, port and password are never printed."""
    return "local" if is_local() else "remote"


def redact(text: str) -> str:
    """`text` without the configured host, port or password (driver errors quote them)."""
    host = f"<{location()} host>"
    for secret, label in ((FALKORDB_PASSWORD, "<password>"), (f"{FALKORDB_HOST}:{FALKORDB_PORT}", host),
                          (FALKORDB_HOST, host)):
        if secret:
            text = text.replace(secret, label)
    return re.sub(rf"(?<!\d){FALKORDB_PORT}(?!\d)", "<port>", text)


def require_local_or_allowed(allow_remote: bool) -> None:
    """Graph writes go to a remote database only when the user said so."""
    if not is_local() and not allow_remote:
        raise RemoteNotAllowed(
            "FALKORDB_HOST points to a remote FalkorDB; scanning would write this project's graph "
            "(its code included) there. Pass --allow-remote to do that, or --offline to write nothing.")


LOCAL_DEFAULT = ("localhost", 6379)     # what `gittrace up` starts


def _client(local_default: bool = False, **timeouts):
    try:
        from falkordb import FalkorDB
    except ImportError as exc:
        raise RuntimeError("falkordb not installed. Run: pip install gittrace (or -r requirements.txt)") from exc
    if local_default:
        return FalkorDB(host=LOCAL_DEFAULT[0], port=LOCAL_DEFAULT[1], **timeouts)
    kwargs: dict = {"host": FALKORDB_HOST, "port": FALKORDB_PORT, **timeouts}
    # Credentials go together or not at all: redis-py sends AUTH whenever a
    # username is set, and AUTH with a username but no password fails to
    # encode, so an unauthenticated server (local Docker, CI) was unreachable.
    if FALKORDB_PASSWORD:
        kwargs["username"] = FALKORDB_USER
        kwargs["password"] = FALKORDB_PASSWORD
    return FalkorDB(**kwargs)


def check(timeout: float = CHECK_TIMEOUT_S, local_default: bool = False) -> tuple[bool, str]:
    """A real round trip: a fresh connection runs GRAPH.LIST (a FalkorDB command,
    so a plain Redis or a wrong password fails) within `timeout` seconds.
    Returns (ok, reason); the reason never names the host. `local_default`
    checks local Docker (LOCAL_DEFAULT) whatever the settings say."""
    try:
        db = _client(local_default, socket_connect_timeout=timeout, socket_timeout=timeout)
        try:
            db.connection.execute_command("GRAPH.LIST")
        finally:
            db.connection.close()
    except Exception as exc:  # noqa: BLE001 - any failure means "down"
        return False, f"{type(exc).__name__}: {redact(str(exc))}"
    return True, "GRAPH.LIST answered"


def get_db():
    """Lazily connect to FalkorDB and reuse the handle."""
    global _db
    if _db is not None:
        return _db

    _db = None
    try:
        _db = _client(socket_connect_timeout=CONNECT_TIMEOUT_S)
        # falkordb has no .ping(); the underlying redis client does.
        _db.connection.ping()
        return _db
    except RuntimeError:
        raise
    except Exception as first_err:  # noqa: BLE001
        # If the handle was created but the ping failed, discard it so a
        # later retry does not reuse a dead connection.
        _db = None
        raise RuntimeError(
            f"cannot connect to the {location()} FalkorDB: {type(first_err).__name__}: {redact(str(first_err))}"
        ) from None


def get_graph(name: str, db=None):
    """The named graph handle (FalkorDB creates the graph on first write)."""
    if db is None:
        db = get_db()
    return db.select_graph(name)
