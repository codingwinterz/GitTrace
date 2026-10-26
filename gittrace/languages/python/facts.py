"""
gittrace.languages.python.facts — imports, entry points, side effects and
services of a Python project, for `gittrace explain`.

Everything here is a deterministic reading of the parsed code; nothing is
guessed from names alone where the code says more:

  imports       every import statement, classified as project (resolves to a
                project file), stdlib (sys.stdlib_module_names) or external.
  entry points  `if __name__ == "__main__":`; click, Typer and Flask CLI
                commands (the decorator must resolve to click, to a
                typer.Typer object, or to `.cli` of a Flask app or blueprint);
                argparse parsers; FastAPI / Flask application objects, created
                at import time (app) or inside a function (app factory).
  effects       calls with an effect outside the program, by the callee's
                full dotted name (aliases expanded by the resolver):
                  subprocess  subprocess.*, os.system/popen/exec*/spawn*, ...
                  network     requests, httpx, aiohttp, urllib.request,
                              urllib3, http.client, socket, smtplib, boto3, ...
                  file_read / file_write
                              open() by its mode literal (read when the mode
                              is absent or has no w/a/x/+), pathlib's
                              read_*/write_*, os and shutil file operations
                  db_read / db_write / db
                              `.execute(...)` by its SQL verb when the SQL
                              text is visible (SELECT/WITH read; INSERT,
                              UPDATE, DELETE, CREATE, ... write; otherwise
                              `db`, direction unknown), SQLAlchemy sessions
                              (add/delete/merge/commit write; query/get/
                              scalars/execute read), `Model.query...`
                              (Flask-SQLAlchemy) and Django's
                              `Model.objects...`, cursor fetch*, MongoDB
                              collection methods, Redis clients.
                A method called on a local object (`cursor.execute`) is
                classified by its name only for these database verbs, which
                are distinctive; `x.get()` or `x.save()` is not an effect.
  services      data stores and outside services, from the imported
                packages (sqlite3, SQLAlchemy, Redis, requests, boto3, ...),
                plus "files on disk" and "other programs" when effects show
                them.
"""

from __future__ import annotations

import re
import sys
from collections import defaultdict
from typing import Iterable, Sequence

from gittrace.languages.base import (
    CallSite,
    EffectFact,
    EntryPointDef,
    ImportFact,
    ServiceFact,
    function_id,
    MODULE_SCOPE,
)
from gittrace.languages.python.parser import PyFunction, PyModule
from gittrace.languages.python.resolver import ExtInst, ExtSym, FuncSym, Resolver, VarSym
from gittrace.languages.python.routes import FASTAPI_APPS, FLASK_APPS, FLASK_BLUEPRINTS as _FLASK_BLUEPRINTS

STDLIB = frozenset(sys.stdlib_module_names)


# -- imports ------------------------------------------------------------------

def imports(modules: Sequence[PyModule], resolver: Resolver) -> list[ImportFact]:
    out = []
    for mod in modules:
        seen = set()
        for module, names, line in mod.imports:
            if not module or module == "__future__":
                continue
            top = module.split(".")[0]
            project = (resolver.lookup_module(module, mod.path) is not None
                       or any(resolver.lookup_module(f"{module}.{n}", mod.path) for n in names)
                       or (top in resolver.index and top not in STDLIB))
            kind = "project" if project else "stdlib" if top in STDLIB else "external"
            if (module, line) not in seen:
                seen.add((module, line))
                out.append(ImportFact(mod.path, line, module, kind, top))
    return out


# -- entry points ---------------------------------------------------------------

_CLICK = frozenset({"click.command", "click.group", "click.decorators.command", "click.decorators.group"})
_CLICK_GROUPS = frozenset({"click.Group", "click.core.Group", "click.group"})
_TYPER = frozenset({"typer.Typer", "typer.main.Typer"})
_ARGPARSE = frozenset({"argparse.ArgumentParser"})


def _command_name(fn: PyFunction, decorator) -> str:
    first = decorator.args[0] if decorator.args else decorator.kwarg("name")
    if first is not None and first.kind == "str" and first.string:
        return first.string
    return fn.record.name.replace("_", "-")


def entry_points(modules: Sequence[PyModule], resolver: Resolver,
                 calls: Sequence[CallSite]) -> list[EntryPointDef]:
    out: list[EntryPointDef] = []
    for mod in modules:
        if mod.main_guard is not None:
            out.append(EntryPointDef("main", function_id(mod.path, MODULE_SCOPE), mod.path, mod.main_guard,
                                     'runs when the file is started directly (`if __name__ == "__main__":`)'))

    def flask_cli(mod, fn, parts) -> bool:
        """`@app.cli.command()` / `@bp.cli.group()` on a Flask app or blueprint."""
        if len(parts) < 3 or parts[-2] != "cli":
            return False
        owner = resolver.resolve_ref(mod, fn.outer, parts[:-2]).sym
        held = resolver.deref(owner) if isinstance(owner, VarSym) else owner
        return isinstance(held, ExtInst) and held.dotted in FLASK_APPS | _FLASK_BLUEPRINTS

    # Groups (@click.group(), @bp.cli.group()): their .command() decorators are commands too.
    groups: dict[str, str] = {}
    for mod in modules:
        for fn in mod.functions:
            for dec in fn.decorators:
                if not dec.parts:
                    continue
                r = resolver.resolve_ref(mod, fn.outer, dec.parts)
                if isinstance(r.sym, ExtSym) and r.sym.dotted in ("click.group", "click.decorators.group"):
                    groups[fn.record.id] = "click"
                elif dec.parts[-1] == "group" and flask_cli(mod, fn, dec.parts):
                    groups[fn.record.id] = "Flask CLI"

    for mod in modules:
        for fn in mod.functions:
            for dec in fn.decorators:
                parts = dec.parts
                if not parts or parts[-1] not in ("command", "group", "callback"):
                    continue
                r = resolver.resolve_ref(mod, fn.outer, parts)
                framework = None
                if isinstance(r.sym, ExtSym) and r.sym.dotted in _CLICK:
                    framework = "click"
                elif flask_cli(mod, fn, parts):
                    framework = "Flask CLI"
                elif len(parts) > 1:
                    owner = resolver.resolve_ref(mod, fn.outer, parts[:-1]).sym
                    held = resolver.deref(owner) if isinstance(owner, VarSym) else owner
                    if isinstance(held, ExtInst) and held.dotted in _TYPER:
                        framework = "Typer"
                    elif isinstance(held, ExtInst) and held.dotted in _CLICK_GROUPS:
                        framework = "click"
                    elif isinstance(held, FuncSym) and held.id in groups:
                        framework = groups[held.id]
                if framework is None:
                    continue
                what = "callback" if parts[-1] == "callback" else parts[-1]
                detail = (f"{framework} {what} `{_command_name(fn, dec)}`" if what != "callback"
                          else f"{framework} callback (runs before every command)")
                out.append(EntryPointDef("cli", fn.record.id, fn.record.file, fn.record.start_line,
                                         f"command-line {detail}"))
                break

    for call in calls:
        if call.resolved:
            continue
        if call.dotted in _ARGPARSE:
            out.append(EntryPointDef("cli", call.caller_id, call.site.file if call.site else _file(call),
                                     call.line, "builds a command-line parser (argparse)"))
        elif call.dotted in FASTAPI_APPS or call.dotted in FLASK_APPS:
            framework = "FastAPI" if call.dotted in FASTAPI_APPS else "Flask"
            file = call.site.file if call.site else _file(call)
            if call.caller_id.endswith(f"::{MODULE_SCOPE}"):
                out.append(EntryPointDef("app", call.caller_id, file, call.line,
                                         f"creates the {framework} application when the module is imported"))
            else:
                out.append(EntryPointDef("app_factory", call.caller_id, file, call.line,
                                         f"creates and returns a {framework} application (an app factory)"))
    return sorted(set(out), key=lambda e: (e.file, e.line, e.kind))


def _file(call: CallSite) -> str:
    return call.caller_id.split("::", 1)[0]


# -- side effects ------------------------------------------------------------

_SUBPROCESS = re.compile(
    r"^(?:subprocess\.\w+|os\.(?:system|popen|exec\w*|spawn\w*|posix_spawn\w*|startfile)"
    r"|asyncio\.create_subprocess_\w+|pty\.spawn|commands\.getoutput|commands\.getstatusoutput)$")
_NETWORK = re.compile(
    r"^(?:requests|httpx|aiohttp|urllib3|http\.client|socket|smtplib|ftplib|paramiko|websockets?|grpc"
    r"|boto3|botocore|imaplib|poplib|telnetlib|xmlrpc\.client|pycurl)\..+$"
    r"|^urllib\.request\.(?:urlopen|urlretrieve|Request)$|^urllib2\.urlopen$")
_FILE_WRITE = re.compile(
    r"^(?:os\.(?:remove|unlink|rmdir|removedirs|rename|renames|replace|makedirs|mkdir|truncate|chmod|chown"
    r"|symlink|link)|shutil\.(?:copy\w*|move|rmtree|make_archive|unpack_archive)|tempfile\.\w+)$")
_FILE_READ = re.compile(r"^(?:os\.(?:listdir|scandir|walk)|glob\.i?glob|shutil\.disk_usage)$")
# Method names on any object: pathlib, and file-like writes.
_PATH_WRITE = frozenset({"write_text", "write_bytes", "touch", "unlink", "mkdir", "rmdir", "rename", "replace"})
_PATH_READ = frozenset({"read_text", "read_bytes", "iterdir", "glob", "rglob"})
_SQL_WRITE = frozenset({"insert", "update", "delete", "replace", "merge", "create", "drop", "alter",
                        "truncate", "upsert", "grant", "revoke"})
_SQL_READ = frozenset({"select", "with", "show", "explain", "pragma", "describe"})
_SESSION_WRITE = frozenset({"add", "add_all", "delete", "merge", "commit", "flush", "bulk_save_objects",
                            "bulk_insert_mappings", "bulk_update_mappings"})
_SESSION_READ = frozenset({"query", "get", "scalars", "scalar", "scalar_one", "scalar_one_or_none",
                           "exec"})
_FETCH = frozenset({"fetchone", "fetchall", "fetchmany", "fetchval", "fetchrow"})
_MONGO_WRITE = frozenset({"insert_one", "insert_many", "update_one", "update_many", "delete_one",
                          "delete_many", "replace_one", "bulk_write", "find_one_and_update",
                          "find_one_and_delete", "find_one_and_replace"})
_MONGO_READ = frozenset({"find", "find_one", "aggregate", "count_documents", "distinct"})
_REDIS_WRITE = frozenset({"set", "setex", "hset", "hmset", "delete", "lpush", "rpush", "sadd", "zadd",
                          "incr", "decr", "expire", "publish", "rpop", "lpop"})
_REDIS_READ = frozenset({"get", "hget", "hgetall", "mget", "lrange", "smembers", "exists", "keys",
                         "zrange", "ttl"})
_DJANGO_WRITE = frozenset({"create", "bulk_create", "update", "delete", "get_or_create", "update_or_create"})
_STRING_PREFIX = re.compile(r"""^[rRbBuUfF]{0,2}(['"]{1,3})""")


def _sql_verb(call: CallSite) -> str | None:
    arg = call.argument(0, "statement", "sql", "query", "operation")
    if arg is None:
        return None
    if arg.is_literal and isinstance(arg.value, str):
        text = arg.value
    else:
        m = _STRING_PREFIX.match(arg.text)
        if m is None:
            # sqlalchemy.text("...") / text("...")
            inner = re.match(r"""^(?:\w+\.)*text\(\s*[rRbBuUfF]{0,2}(['"]{1,3})(.*)""", arg.text, re.S)
            if inner is None:
                return None
            text = inner.group(2)
        else:
            text = arg.text[m.end():]
    word = re.match(r"\s*\(?\s*([A-Za-z]+)", text)
    return word.group(1).lower() if word else None


def _open_mode(call: CallSite) -> str:
    mode = call.argument(1, "mode")
    if mode is None:
        return "r"
    if mode.is_literal and isinstance(mode.value, str):
        return mode.value
    return "?"


def classify(call: CallSite) -> tuple[str, str] | None:
    """(effect kind, detail) for one unresolved call, or None."""
    d = call.dotted
    last = d.rsplit(".", 1)[-1]
    lower = d.lower()
    if _SUBPROCESS.match(d):
        return "subprocess", d
    if _NETWORK.match(d):
        return "network", d
    if d in ("open", "io.open", "codecs.open", "os.open") and call.origin in ("builtin", "import"):
        mode = _open_mode(call)
        if mode == "?":
            return "file_read", "open() with a mode that is not a constant"
        write = any(c in mode for c in "wax+")
        return ("file_write" if write else "file_read"), f'open(..., "{mode}")'
    if _FILE_WRITE.match(d):
        return "file_write", d
    if _FILE_READ.match(d):
        return "file_read", d
    if call.origin == "builtin":
        return None

    # Methods on objects: database verbs first (distinctive names).
    if last in ("execute", "executemany", "executescript", "exec_driver_sql"):
        verb = _sql_verb(call)
        if verb in _SQL_READ:
            return "db_read", f"SQL {verb.upper()}"
        if verb in _SQL_WRITE:
            return "db_write", f"SQL {verb.upper()}"
        if last == "executemany":
            return "db_write", "SQL executed for many rows"
        if "session" in lower and verb is None and last == "execute":
            return "db", f"{d} (statement built elsewhere)"
        return "db", "SQL whose text is built elsewhere" if verb is None else f"SQL {verb.upper()}"
    if last in _FETCH:
        return "db_read", f"{d}"
    if ".objects." in d or d.endswith(".objects"):            # Django ORM
        return ("db_write" if last in _DJANGO_WRITE else "db_read"), f"Django ORM {last}"
    if ".query." in d or d.endswith(".query"):                # Flask-SQLAlchemy Model.query...
        return "db_read", f"SQLAlchemy query ({last})"
    if "session" in lower:
        if last in _SESSION_WRITE:
            return "db_write", f"database session {last}"
        if last in _SESSION_READ:
            return "db_read", f"database session {last}"
    if last == "commit" and re.search(r"\b(?:db|conn|connection|cnx|con|database|transaction)\b",
                                      lower.replace(".", " ")):
        return "db_write", f"{d}"
    if "collection" in lower or re.search(r"\bdb\b|\bmongo", lower.replace(".", " ")):
        if last in _MONGO_WRITE:
            return "db_write", f"MongoDB {last}"
        if last in _MONGO_READ and last != "distinct":
            return "db_read", f"MongoDB {last}"
    if "redis" in lower or lower.startswith("cache."):
        if last in _REDIS_WRITE:
            return "db_write", f"Redis {last}"
        if last in _REDIS_READ:
            return "db_read", f"Redis {last}"
    if call.origin == "unknown" and last in _PATH_WRITE and last not in ("replace", "rename", "unlink"):
        return "file_write", f".{last}()"
    if call.origin == "unknown" and last in _PATH_READ:
        return "file_read", f".{last}()"
    return None


def effects(calls: Sequence[CallSite]) -> list[EffectFact]:
    out = []
    for call in calls:
        if call.resolved or call.origin == "class":
            continue
        kind = classify(call)
        if kind is None:
            continue
        file = call.site.file if call.site else _file(call)
        out.append(EffectFact(call.caller_id, file, call.line, kind[0], call.dotted, kind[1]))
    # `conn.execute(sql).fetchall()` is one database access, not two: on one
    # line keep the execute (it knows the SQL verb) over the fetch.
    kept: dict[tuple, EffectFact] = {}
    for e in out:
        key = (e.function_id, e.line, "db") if e.kind.startswith("db") else (e.function_id, e.line, e.kind,
                                                                            e.callee)
        prev = kept.get(key)
        if prev is None or (e.callee.rsplit(".", 1)[-1].startswith("execute")
                            and not prev.callee.rsplit(".", 1)[-1].startswith("execute")):
            kept[key] = e
    return sorted(kept.values(), key=lambda e: (e.file, e.line, e.kind))


# -- services ---------------------------------------------------------------

# top-level package -> (kind, name, explanation)
_SERVICES: dict[str, tuple[str, str, str]] = {
    "sqlite3": ("database", "SQLite",
                "a SQL database kept in a single file on disk"),
    "sqlalchemy": ("database", "SQL database through SQLAlchemy",
                   "SQLAlchemy is an ORM: it maps Python classes to database tables and writes the SQL"),
    "flask_sqlalchemy": ("database", "SQL database through Flask-SQLAlchemy",
                         "SQLAlchemy wired into Flask: Python classes mapped to database tables"),
    "sqlmodel": ("database", "SQL database through SQLModel",
                 "SQLModel maps Python classes to database tables (built on SQLAlchemy)"),
    "psycopg2": ("database", "PostgreSQL", "a SQL database server"),
    "psycopg": ("database", "PostgreSQL", "a SQL database server"),
    "asyncpg": ("database", "PostgreSQL", "a SQL database server"),
    "pymysql": ("database", "MySQL", "a SQL database server"),
    "MySQLdb": ("database", "MySQL", "a SQL database server"),
    "mysql": ("database", "MySQL", "a SQL database server"),
    "peewee": ("database", "SQL database through peewee", "peewee maps Python classes to database tables"),
    "tortoise": ("database", "SQL database through Tortoise ORM",
                 "Tortoise maps Python classes to database tables"),
    "pymongo": ("database", "MongoDB", "a document database: it stores JSON-like records, not tables"),
    "motor": ("database", "MongoDB", "a document database: it stores JSON-like records, not tables"),
    "mongoengine": ("database", "MongoDB", "a document database: it stores JSON-like records, not tables"),
    "redis": ("cache", "Redis", "an in-memory key-value store, often used as a cache or a message queue"),
    "aioredis": ("cache", "Redis", "an in-memory key-value store, often used as a cache or a message queue"),
    "elasticsearch": ("search", "Elasticsearch", "a search engine server that indexes text for fast search"),
    "requests": ("http", "outbound HTTP (requests)", "the app calls other web services over HTTP"),
    "httpx": ("http", "outbound HTTP (httpx)", "the app calls other web services over HTTP"),
    "aiohttp": ("http", "outbound HTTP (aiohttp)", "the app calls other web services over HTTP"),
    "urllib3": ("http", "outbound HTTP (urllib3)", "the app calls other web services over HTTP"),
    "smtplib": ("email", "email over SMTP", "the app sends email through a mail server"),
    "flask_mail": ("email", "email (Flask-Mail)", "the app sends email through a mail server"),
    "celery": ("queue", "Celery task queue", "work is handed to background workers through a queue"),
    "rq": ("queue", "RQ task queue (on Redis)", "work is handed to background workers through a Redis queue"),
    "pika": ("queue", "RabbitMQ", "a message queue server"),
    "kafka": ("queue", "Kafka", "a message streaming server"),
    "boto3": ("cloud", "AWS (boto3)", "the app calls Amazon Web Services (storage, queues, ...)"),
    "openai": ("ai", "OpenAI API", "the app sends text to a hosted AI model"),
    "anthropic": ("ai", "Anthropic API", "the app sends text to a hosted AI model"),
    "litellm": ("ai", "AI models through LiteLLM", "the app sends text to AI models"),
    "stripe": ("payments", "Stripe", "online payments"),
}


def services(import_facts: Iterable[ImportFact], effect_facts: Sequence[EffectFact]) -> list[ServiceFact]:
    found: dict[str, tuple[tuple[str, str, str], list[str]]] = {}
    for imp in import_facts:
        if imp.kind == "project":
            continue
        if imp.module.startswith("urllib.request") or imp.module.startswith("http.client"):
            spec = ("http", "outbound HTTP (standard library)", "the app calls other web services over HTTP")
        else:
            spec = _SERVICES.get(imp.package)
        if spec is None:
            continue
        found.setdefault(spec[1], (spec, []))[1].append(f"{imp.file}:{imp.line} imports {imp.module}")
    out = [ServiceFact(spec[0], name, spec[2], tuple(ev[:3]) + ((f"... and {len(ev) - 3} more",)
                                                                  if len(ev) > 3 else ()))
           for name, (spec, ev) in found.items()]

    by_kind: dict[str, list[EffectFact]] = defaultdict(list)
    for e in effect_facts:
        by_kind[e.kind].append(e)
    if by_kind["file_write"]:
        ev = [f"{e.file}:{e.line} {e.detail or e.callee}" for e in by_kind["file_write"]]
        out.append(ServiceFact("files", "files on disk", "the app writes or deletes files on the machine it runs on",
                               tuple(ev[:3]) + ((f"... and {len(ev) - 3} more",) if len(ev) > 3 else ())))
    if by_kind["subprocess"]:
        ev = [f"{e.file}:{e.line} {e.callee}" for e in by_kind["subprocess"]]
        out.append(ServiceFact("programs", "other programs", "the app starts other programs on the machine "
                               "(shell commands)",
                               tuple(ev[:3]) + ((f"... and {len(ev) - 3} more",) if len(ev) > 3 else ())))
    order = ["database", "cache", "search", "queue", "http", "email", "cloud", "ai", "payments", "files",
             "programs"]
    return sorted(out, key=lambda s: (order.index(s.kind), s.name))
