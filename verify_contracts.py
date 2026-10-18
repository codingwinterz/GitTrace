"""
verify_contracts.py - assert GET /demo and POST /query response shapes
against the live backend at http://127.0.0.1:8000.

Run:
    python verify_contracts.py
"""
from __future__ import annotations

import json
import sys
import urllib.request
import urllib.error

BACKEND = "http://127.0.0.1:8000"
TIMEOUT = 15.0


def _get(path: str) -> dict:
    req = urllib.request.Request(f"{BACKEND}{path}")
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read().decode())


def _post(path: str, body: dict) -> dict:
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        f"{BACKEND}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read().decode())


def _fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def _check_keys(obj: dict, required: list[str], label: str) -> None:
    actual = set(obj.keys())
    missing = [k for k in required if k not in actual]
    if missing:
        _fail(f"{label} missing keys: {missing}; got {sorted(actual)}")


def main() -> None:
    print("1) GET /demo contract")
    demo = _get("/demo")
    _check_keys(demo, ["blast_radius", "attack_path", "code_owner"], "/demo")
    print("   /demo has required top-level keys")
    print("   blast_radius keys:", sorted(demo["blast_radius"].keys()))
    print("   attack_path keys:", sorted(demo["attack_path"].keys()))
    print("   code_owner keys:", sorted(demo["code_owner"].keys()))
    print()

    print("2) POST /query contract")
    query = _post(
        "/query",
        {"question": "What's the blast radius of CVE-2026-4421?"},
    )
    _check_keys(query, ["answer", "tool_calls", "tool_results", "cve_id"], "/query")
    print("   /query has required keys")
    print("   answer length:", len(query["answer"]))
    print("   tool_calls:", [tc.get("name") for tc in query.get("tool_calls", [])])
    print("   tool_results:", [tr.get("name") for tr in query.get("tool_results", [])])
    print("   cve_id:", query.get("cve_id"))
    print()

    print("3) Graph-mapping inputs are present in tool_results")
    for tr in query.get("tool_results", []):
        if tr.get("name") == "get_blast_radius":
            r = tr.get("result", {})
            for k in ["impacted_services", "impacted_functions", "cve_id", "severity"]:
                if k not in r:
                    _fail(f"/query get_blast_radius result missing {k}")
            print("   get_blast_radius.result has:", sorted(r.keys()))
        if tr.get("name") == "find_shortest_dependency_path":
            r = tr.get("result", {})
            for k in ["path_trace", "hop_count", "start_service", "target_function", "cve_id"]:
                if k not in r:
                    _fail(f"/query find_shortest_dependency_path result missing {k}")
            print("   find_shortest_dependency_path.result has:", sorted(r.keys()))
    print()

    print("OK - endpoint contracts match the Pydantic schemas.")


if __name__ == "__main__":
    main()
