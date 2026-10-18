"""
seed_graph.py — GitTrace Phase 2

Connects to FalkorDB Cloud and seeds the gittrace graph with the schema and
mock data from SPEC.md, using pure Cypher via graph.query() (the installed
falkordb 1.8.0 exposes no ORM-style create/create_edge helpers).

Demo scenario wired:
  - CVE-2026-4421 (CRITICAL) affects token-service.validate_token
  - Public entry: api-gateway --DEPENDS_ON--> auth-service --CONTAINS--> auth.go --DEFINES--> validate_token  (4 hops)
  - Code owner: Sarah Chen (sarah.chen@acme.com, @sarahc)

Env vars (from .env):
    FALKORDB_HOST / FALKORDB_PORT / FALKORDB_USER / FALKORDB_PASSWORD
"""

from __future__ import annotations

import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")

from utils import get_db  # noqa: E402  (after load_dotenv so .env is visible)

GRAPH_NAME = "gittrace"


def run(g, cypher: str, params: dict | None = None) -> None:
    """Execute one Cypher statement; swallow 'already exists' style errors."""
    try:
        g.query(cypher, params=params)
    except Exception as exc:  # noqa: BLE001
        msg = str(exc)
        # Node/edge already present on re-run: ignore.
        if "already exists" in msg.lower() or "duplicate" in msg.lower():
            return
        print(f"  query failed: {msg[:200]}", file=sys.stderr)
        raise


def seed(db) -> None:
    graph_name = GRAPH_NAME

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
    services = [
        ("api-gateway", "Python", 8080, True),
        ("auth-service", "Go", 8081, True),
        ("token-service", "Python", 8082, False),
        ("user-service", "Node.js", 8083, False),
        ("billing-service", "Python", 8084, False),
        ("notification-service", "Go", 8085, False),
        ("web-frontend", "TypeScript", 3000, True),
    ]
    for name, lang, port, is_public in services:
        run(g, (
            'CREATE (s:Service {name: $name, language: $lang, '
            'port: $port, is_public: $is_public})'
        ), {"name": name, "lang": lang, "port": port, "is_public": is_public})
    print(f"  services: {len(services)}")

    # ------------------------------------------------------------------
    # 2) Files + Functions (scoped per service, linked via CONTAINS/DEFINES)
    # ------------------------------------------------------------------
    service_files = {
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

    total_functions = 0
    for svc_name, (file_path, funcs) in service_files.items():
        # File node + CONTAINS edge from the service
        run(g, (
            'MATCH (s:Service {name: $svc}) '
            'CREATE (f:File {path: $path}) '
            'CREATE (s)-[:CONTAINS]->(f)'
        ), {"svc": svc_name, "path": file_path})

        for fname, line, is_entry in funcs:
            run(g, (
                'MATCH (f:File {path: $path}) '
                'CREATE (fn:Function {name: $name, line_number: $line, '
                'is_entry_point: $entry}) '
                'CREATE (f)-[:DEFINES]->(fn)'
            ), {"path": file_path, "name": fname, "line": line, "entry": is_entry})
            total_functions += 1
    print(f"  files: {len(service_files)}, functions: {total_functions}")

    # ------------------------------------------------------------------
    # 3) Developers + OWNS (to Service) + AUTHORED (to File)
    # ------------------------------------------------------------------
    developers = [
        ("Sarah Chen", "sarah.chen@acme.com", "@sarahc"),
        ("Marcus Johnson", "marcus.j@acme.com", "@marcusj"),
        ("Priya Nair", "priya.nair@acme.com", "@priyan"),
        ("Devon Park", "devon.park@acme.com", "@devonp"),
    ]
    for name, email, slack in developers:
        run(g, (
            'CREATE (d:Developer {name: $name, email: $email, '
            'slack_handle: $slack})'
        ), {"name": name, "email": email, "slack": slack})

    ownership = [
        ("Sarah Chen", "auth-service"),
        ("Sarah Chen", "token-service"),
        ("Marcus Johnson", "api-gateway"),
        ("Priya Nair", "user-service"),
        ("Devon Park", "billing-service"),
        ("Devon Park", "notification-service"),
        ("Priya Nair", "web-frontend"),
    ]
    for dev_name, svc_name in ownership:
        run(g, (
            'MATCH (d:Developer {name: $dev}), (s:Service {name: $svc}) '
            'CREATE (d)-[:OWNS]->(s)'
        ), {"dev": dev_name, "svc": svc_name})

    authored = [
        ("Sarah Chen", "auth-service"),
        ("Sarah Chen", "token-service"),
        ("Marcus Johnson", "api-gateway"),
        ("Priya Nair", "user-service"),
        ("Devon Park", "billing-service"),
        ("Devon Park", "notification-service"),
        ("Priya Nair", "web-frontend"),
    ]
    for dev_name, svc_name in authored:
        file_path = service_files[svc_name][0]
        run(g, (
            'MATCH (d:Developer {name: $dev}), (f:File {path: $path}) '
            'CREATE (d)-[:AUTHORED]->(f)'
        ), {"dev": dev_name, "path": file_path})
    print(f"  developers: {len(developers)}")

    # ------------------------------------------------------------------
    # 4) CVEs + AFFECTS edges
    # ------------------------------------------------------------------
    cves = [
        ("CVE-2026-4421", "CRITICAL",
         "Token validation bypass in validate_token allows forged JWTs"),
        ("CVE-2026-5513", "HIGH",
         "SQL injection in get_user_profile via unsanitized user_id param"),
    ]
    for cve_id, severity, desc in cves:
        run(g, (
            'CREATE (c:CVE {id: $id, severity: $sev, description: $desc})'
        ), {"id": cve_id, "sev": severity, "desc": desc})

    # CVE-2026-4421 -> token-service.validate_token
    run(g, (
        'MATCH (c:CVE {id: $cve}) '
        'MATCH (f:File {path: $path})-[:DEFINES]->(fn:Function {name: $fn}) '
        'CREATE (c)-[:AFFECTS]->(fn)'
    ), {"cve": "CVE-2026-4421", "path": "/token-service/token.py",
        "fn": "validate_token"})

    # CVE-2026-5513 -> user-service.get_user_profile
    run(g, (
        'MATCH (c:CVE {id: $cve}) '
        'MATCH (f:File {path: $path})-[:DEFINES]->(fn:Function {name: $fn}) '
        'CREATE (c)-[:AFFECTS]->(fn)'
    ), {"cve": "CVE-2026-5513", "path": "/user-service/users.js",
        "fn": "get_user_profile"})
    print(f"  cves: {len(cves)}")

    # ------------------------------------------------------------------
    # 5) API endpoints + EXPOSES edges
    # ------------------------------------------------------------------
    endpoints = [
        ("POST", "/api/login", "/web-frontend/App.tsx", "submit_login"),
        ("POST", "/api/auth/validate", "/token-service/token.py", "validate_token"),
        ("GET", "/api/users/:id", "/user-service/users.js", "get_user_profile"),
        ("POST", "/api/payments", "/billing-service/billing.py", "process_payment"),
        ("GET", "/api/health", "/api-gateway/main.py", "handle_request"),
    ]
    for method, path, file_path, func_name in endpoints:
        run(g, (
            'CREATE (e:APIEndpoint {path: $path, method: $method})'
        ), {"path": path, "method": method})
        run(g, (
            'MATCH (e:APIEndpoint {path: $path, method: $method}) '
            'MATCH (f:File {path: $fpath})-[:DEFINES]->(fn:Function {name: $fn}) '
            'CREATE (e)-[:EXPOSES]->(fn)'
        ), {"path": path, "method": method, "fpath": file_path, "fn": func_name})
    print(f"  endpoints: {len(endpoints)}")

    # ------------------------------------------------------------------
    # 6) CALLS edges (within-service, scoped by file path to avoid
    #    the validate_token name collision between auth-service and
    #    token-service)
    # ------------------------------------------------------------------
    def calls(src_path: str, src_fn: str, dst_path: str, dst_fn: str) -> None:
        run(g, (
            'MATCH (f1:File {path: $p1})-[:DEFINES]->(a:Function {name: $n1}) '
            'MATCH (f2:File {path: $p2})-[:DEFINES]->(b:Function {name: $n2}) '
            'CREATE (a)-[:CALLS]->(b)'
        ), {"p1": src_path, "n1": src_fn, "p2": dst_path, "n2": dst_fn})

    # api-gateway
    gw = "/api-gateway/main.py"
    calls(gw, "handle_request", gw, "route_request")
    calls(gw, "route_request", "/auth-service/auth.go", "validate_token")
    calls(gw, "handle_request", gw, "log_request")

    # auth-service
    ag = "/auth-service/auth.go"
    calls(ag, "validate_token", ag, "token_blacklist_check")
    calls(ag, "issue_token", ag, "validate_token")
    calls(ag, "refresh_token", ag, "validate_token")

    # token-service
    tp = "/token-service/token.py"
    calls(tp, "validate_token", tp, "parse_claims")
    calls(tp, "refresh_token", tp, "validate_token")
    calls(tp, "rotate_key", tp, "validate_token")

    # user-service
    us = "/user-service/users.js"
    calls(us, "get_user_profile", us, "update_user")
    calls(us, "delete_user", us, "get_user_profile")

    # billing-service
    bs = "/billing-service/billing.py"
    calls(bs, "process_payment", bs, "generate_invoice")
    calls(bs, "void_transaction", bs, "process_payment")

    # notification-service
    ns = "/notification-service/notify.go"
    calls(ns, "send_email", ns, "format_message")
    calls(ns, "send_push", ns, "format_message")

    # web-frontend
    wf = "/web-frontend/App.tsx"
    calls(wf, "submit_login", wf, "fetch_user_data")
    calls(wf, "render_login", wf, "submit_login")

    # ------------------------------------------------------------------
    # 7) DEPENDS_ON edges (service -> service)
    # ------------------------------------------------------------------
    depends = [
        ("token-service", "auth-service"),
        ("api-gateway", "auth-service"),
        ("api-gateway", "token-service"),
        ("web-frontend", "api-gateway"),
        ("user-service", "api-gateway"),
        ("billing-service", "api-gateway"),
        ("notification-service", "user-service"),
    ]
    for child, parent in depends:
        run(g, (
            'MATCH (a:Service {name: $a}), (b:Service {name: $b}) '
            'CREATE (a)-[:DEPENDS_ON]->(b)'
        ), {"a": child, "b": parent})
    print(f"  depends_on: {len(depends)}")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("\nDemo scenario wired:")
    print("  - CVE-2026-4421 (CRITICAL) affects token-service.validate_token")
    print("  - Public entry: api-gateway -> auth-service -> auth.go -> validate_token")
    print("  - Code owner: Sarah Chen (sarah.chen@acme.com, @sarahc)")


def main() -> None:
    print("GitTrace seed_graph.py")
    print("=" * 60)
    db = get_db()
    seed(db)
    print("=" * 60)
    print("Done.")


if __name__ == "__main__":
    main()
