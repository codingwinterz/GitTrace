"""
gittrace.graph.seed — seed FalkorDB with the demo microservice graph.

Connects to FalkorDB and seeds the gittrace graph with the schema and mock
data from docs/archive/SPEC.md, using pure Cypher via graph.query() (the installed
falkordb 1.8.0 exposes no ORM-style create/create_edge helpers).

Run from the repository root:
    python -m gittrace.graph.seed

Demo scenario wired:
  - CVE-2026-4421 (CRITICAL) affects token-service.validate_token
  - Public entry: api-gateway --DEPENDS_ON--> token-service --CONTAINS--> token.py --DEFINES--> validate_token  (3 hops)
  - Code owner: Sarah Chen (sarah.chen@acme.com, @sarahc)

The seed data lives in module-level constants so the offline suite can check
that every edge references a node that is actually defined, without a DB.

Env vars (from .env):
    FALKORDB_HOST / FALKORDB_PORT / FALKORDB_USER / FALKORDB_PASSWORD
    GITTRACE_GRAPH (optional, defaults to "gittrace")
"""

from __future__ import annotations

import sys

from gittrace.graph import connection

# ---------------------------------------------------------------------------
# Seed data
# ---------------------------------------------------------------------------

# (name, language, port, is_public)
SERVICES = [
    ("api-gateway", "Python", 8080, True),
    ("auth-service", "Go", 8081, True),
    ("token-service", "Python", 8082, False),
    ("user-service", "Node.js", 8083, False),
    ("billing-service", "Python", 8084, False),
    ("notification-service", "Go", 8085, False),
    ("web-frontend", "TypeScript", 3000, True),
]

# service -> (file path, [(function name, line, is_entry_point)])
SERVICE_FILES = {
    "api-gateway": ("/api-gateway/main.py", [
        ("handle_request", 24, True),
        ("route_request", 60, False),
        ("log_request", 110, False),
    ]),
    "auth-service": ("/auth-service/auth.go", [
        ("validate_token", 18, True),
        ("issue_token", 88, True),
        ("refresh_token", 140, False),
        ("token_blacklist_check", 200, False),
    ]),
    "token-service": ("/token-service/token.py", [
        ("validate_token", 12, True),
        ("parse_claims", 55, False),
        ("rotate_key", 90, False),
        ("refresh_token", 130, False),
    ]),
    "user-service": ("/user-service/users.js", [
        ("get_user_profile", 22, True),
        ("update_user", 70, False),
        ("delete_user", 120, False),
    ]),
    "billing-service": ("/billing-service/billing.py", [
        ("process_payment", 15, True),
        ("generate_invoice", 60, False),
        ("void_transaction", 110, False),
    ]),
    "notification-service": ("/notification-service/notify.go", [
        ("send_email", 20, True),
        ("send_push", 65, False),
        ("format_message", 100, False),
    ]),
    "web-frontend": ("/web-frontend/App.tsx", [
        ("render_login", 30, True),
        ("submit_login", 80, True),
        ("fetch_user_data", 130, False),
    ]),
}

# (name, email, slack handle)
DEVELOPERS = [
    ("Sarah Chen", "sarah.chen@acme.com", "@sarahc"),
    ("Marcus Johnson", "marcus.j@acme.com", "@marcusj"),
    ("Priya Nair", "priya.nair@acme.com", "@priyan"),
    ("Devon Park", "devon.park@acme.com", "@devonp"),
]

# (developer, service): OWNS goes to the service, AUTHORED to its file.
OWNERSHIP = [
    ("Sarah Chen", "auth-service"),
    ("Sarah Chen", "token-service"),
    ("Marcus Johnson", "api-gateway"),
    ("Priya Nair", "user-service"),
    ("Devon Park", "billing-service"),
    ("Devon Park", "notification-service"),
    ("Priya Nair", "web-frontend"),
]
AUTHORED = list(OWNERSHIP)

# (id, severity, description, affected file path, affected function)
CVES = [
    ("CVE-2026-4421", "CRITICAL",
     "Token validation bypass in validate_token allows forged JWTs",
     "/token-service/token.py", "validate_token"),
    ("CVE-2026-5513", "HIGH",
     "SQL injection in get_user_profile via unsanitized user_id param",
     "/user-service/users.js", "get_user_profile"),
]

# (method, route, handler file path, handler function)
ENDPOINTS = [
    ("POST", "/api/login", "/web-frontend/App.tsx", "submit_login"),
    ("POST", "/api/auth/validate", "/token-service/token.py", "validate_token"),
    ("GET", "/api/users/:id", "/user-service/users.js", "get_user_profile"),
    ("POST", "/api/payments", "/billing-service/billing.py", "process_payment"),
    ("GET", "/api/health", "/api-gateway/main.py", "handle_request"),
]

_GW = "/api-gateway/main.py"
_AG = "/auth-service/auth.go"
_TP = "/token-service/token.py"
_US = "/user-service/users.js"
_BS = "/billing-service/billing.py"
_NS = "/notification-service/notify.go"
_WF = "/web-frontend/App.tsx"

# (caller file, caller, callee file, callee). Both ends are scoped by file path
# because validate_token and refresh_token exist in two services.
CALL_EDGES = [
    # api-gateway
    (_GW, "handle_request", _GW, "route_request"),
    (_GW, "route_request", _AG, "validate_token"),
    (_GW, "handle_request", _GW, "log_request"),
    # auth-service
    (_AG, "validate_token", _AG, "token_blacklist_check"),
    (_AG, "issue_token", _AG, "validate_token"),
    (_AG, "refresh_token", _AG, "validate_token"),
    # token-service
    (_TP, "validate_token", _TP, "parse_claims"),
    (_TP, "refresh_token", _TP, "validate_token"),
    (_TP, "rotate_key", _TP, "validate_token"),
    # user-service
    (_US, "get_user_profile", _US, "update_user"),
    (_US, "delete_user", _US, "get_user_profile"),
    # billing-service
    (_BS, "process_payment", _BS, "generate_invoice"),
    (_BS, "void_transaction", _BS, "process_payment"),
    # notification-service
    (_NS, "send_email", _NS, "format_message"),
    (_NS, "send_push", _NS, "format_message"),
    # web-frontend
    (_WF, "submit_login", _WF, "fetch_user_data"),
    (_WF, "render_login", _WF, "submit_login"),
]

# (dependent service, service it depends on)
DEPENDS = [
    ("token-service", "auth-service"),
    ("api-gateway", "auth-service"),
    ("api-gateway", "token-service"),
    ("web-frontend", "api-gateway"),
    ("user-service", "api-gateway"),
    ("billing-service", "api-gateway"),
    ("notification-service", "user-service"),
]


def run(g, cypher: str, params: dict | None = None):
    """Execute one Cypher statement; swallow 'already exists' style errors."""
    try:
        return g.query(cypher, params=params)
    except Exception as exc:  # noqa: BLE001
        msg = str(exc)
        # Node/edge already present on re-run: ignore.
        if "already exists" in msg.lower() or "duplicate" in msg.lower():
            return None
        print(f"  query failed: {msg[:200]}", file=sys.stderr)
        raise


def link(g, cypher: str, params: dict) -> None:
    """Create exactly one relationship, or fail.

    MATCH ... CREATE is silent when the MATCH finds nothing, which is how a
    CALLS edge to a function the file never defines used to vanish without a
    trace. Every edge in the seed is meant to exist, so a zero (or a fan-out
    from an ambiguous match) is a seed bug worth stopping on.
    """
    result = run(g, cypher, params)
    created = result.relationships_created if result is not None else 0
    if created != 1:
        raise RuntimeError(
            f"expected 1 relationship, created {created}: {cypher.strip()} {params}"
        )


def seed(db, graph_name: str | None = None) -> None:
    graph_name = graph_name or connection.GRAPH_NAME

    # Reset in place before inserting. This is a hard, unconditional wipe: the
    # old list_graphs()/delete() path swallowed every exception, so a failed
    # drop silently produced a doubled graph full of duplicate nodes.
    g = db.select_graph(graph_name)
    run(g, "MATCH (n) DETACH DELETE n")
    remaining = g.query("MATCH (n) RETURN count(n)").result_set[0][0]
    print(f"Reset graph '{graph_name}' ({remaining} nodes remaining)")

    # ------------------------------------------------------------------
    # 1) Services
    # ------------------------------------------------------------------
    for name, lang, port, is_public in SERVICES:
        run(g, (
            'CREATE (s:Service {name: $name, language: $lang, '
            'port: $port, is_public: $is_public})'
        ), {"name": name, "lang": lang, "port": port, "is_public": is_public})
    print(f"  services: {len(SERVICES)}")

    # ------------------------------------------------------------------
    # 2) Files + Functions (scoped per service, linked via CONTAINS/DEFINES)
    # ------------------------------------------------------------------
    total_functions = 0
    for svc_name, (file_path, funcs) in SERVICE_FILES.items():
        # File node + CONTAINS edge from the service
        link(g, (
            'MATCH (s:Service {name: $svc}) '
            'CREATE (f:File {path: $path}) '
            'CREATE (s)-[:CONTAINS]->(f)'
        ), {"svc": svc_name, "path": file_path})

        for fname, line, is_entry in funcs:
            link(g, (
                'MATCH (f:File {path: $path}) '
                'CREATE (fn:Function {name: $name, line_number: $line, '
                'is_entry_point: $entry}) '
                'CREATE (f)-[:DEFINES]->(fn)'
            ), {"path": file_path, "name": fname, "line": line, "entry": is_entry})
            total_functions += 1
    print(f"  files: {len(SERVICE_FILES)}, functions: {total_functions}")

    # ------------------------------------------------------------------
    # 3) Developers + OWNS (to Service) + AUTHORED (to File)
    # ------------------------------------------------------------------
    for name, email, slack in DEVELOPERS:
        run(g, (
            'CREATE (d:Developer {name: $name, email: $email, '
            'slack_handle: $slack})'
        ), {"name": name, "email": email, "slack": slack})

    for dev_name, svc_name in OWNERSHIP:
        link(g, (
            'MATCH (d:Developer {name: $dev}), (s:Service {name: $svc}) '
            'CREATE (d)-[:OWNS]->(s)'
        ), {"dev": dev_name, "svc": svc_name})

    for dev_name, svc_name in AUTHORED:
        file_path = SERVICE_FILES[svc_name][0]
        link(g, (
            'MATCH (d:Developer {name: $dev}), (f:File {path: $path}) '
            'CREATE (d)-[:AUTHORED]->(f)'
        ), {"dev": dev_name, "path": file_path})
    print(f"  developers: {len(DEVELOPERS)}")

    # ------------------------------------------------------------------
    # 4) CVEs + AFFECTS edges
    # ------------------------------------------------------------------
    for cve_id, severity, desc, file_path, func_name in CVES:
        run(g, (
            'CREATE (c:CVE {id: $id, severity: $sev, description: $desc})'
        ), {"id": cve_id, "sev": severity, "desc": desc})
        link(g, (
            'MATCH (c:CVE {id: $cve}) '
            'MATCH (f:File {path: $path})-[:DEFINES]->(fn:Function {name: $fn}) '
            'CREATE (c)-[:AFFECTS]->(fn)'
        ), {"cve": cve_id, "path": file_path, "fn": func_name})
    print(f"  cves: {len(CVES)}")

    # ------------------------------------------------------------------
    # 5) API endpoints + EXPOSES edges
    # ------------------------------------------------------------------
    for method, path, file_path, func_name in ENDPOINTS:
        run(g, (
            'CREATE (e:APIEndpoint {path: $path, method: $method})'
        ), {"path": path, "method": method})
        link(g, (
            'MATCH (e:APIEndpoint {path: $path, method: $method}) '
            'MATCH (f:File {path: $fpath})-[:DEFINES]->(fn:Function {name: $fn}) '
            'CREATE (e)-[:EXPOSES]->(fn)'
        ), {"path": path, "method": method, "fpath": file_path, "fn": func_name})
    print(f"  endpoints: {len(ENDPOINTS)}")

    # ------------------------------------------------------------------
    # 6) CALLS edges, both ends scoped by file path
    # ------------------------------------------------------------------
    for src_path, src_fn, dst_path, dst_fn in CALL_EDGES:
        link(g, (
            'MATCH (f1:File {path: $p1})-[:DEFINES]->(a:Function {name: $n1}) '
            'MATCH (f2:File {path: $p2})-[:DEFINES]->(b:Function {name: $n2}) '
            'CREATE (a)-[:CALLS]->(b)'
        ), {"p1": src_path, "n1": src_fn, "p2": dst_path, "n2": dst_fn})
    print(f"  calls: {len(CALL_EDGES)}")

    # ------------------------------------------------------------------
    # 7) DEPENDS_ON edges (service -> service)
    # ------------------------------------------------------------------
    for child, parent in DEPENDS:
        link(g, (
            'MATCH (a:Service {name: $a}), (b:Service {name: $b}) '
            'CREATE (a)-[:DEPENDS_ON]->(b)'
        ), {"a": child, "b": parent})
    print(f"  depends_on: {len(DEPENDS)}")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("\nDemo scenario wired:")
    print("  - CVE-2026-4421 (CRITICAL) affects token-service.validate_token")
    print("  - Public entry: api-gateway -> token-service -> token.py -> validate_token (3 hops)")
    print("  - Code owner: Sarah Chen (sarah.chen@acme.com, @sarahc)")


def main() -> None:
    print("GitTrace graph seed")
    print("=" * 60)
    db = connection.get_db()
    seed(db)
    print("=" * 60)
    print("Done.")


if __name__ == "__main__":
    main()
