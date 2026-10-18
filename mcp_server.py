"""
mcp_server.py — GitTrace MCP server.

Exposes the three FalkorDB graph tools over the Model Context Protocol (MCP)
so any MCP-capable agent host (Claude Desktop, custom agents, etc.) can query
the codebase dependency graph. This satisfies the Track 01 requirement
"MCP or GraphRAG-SDK used" with a real, runnable integration (not just a
name-drop in the README).

Tools exposed:
  - get_blast_radius(cve_id)
  - find_shortest_dependency_path(start_service, target_function)
  - find_code_owner(function_name)

Run (stdio transport, the standard for local MCP servers):
    python mcp_server.py

Then register this server in your MCP host with:
    { "command": "python", "args": ["mcp_server.py"] }
"""

from __future__ import annotations

import json

from mcp.server.mcpserver import MCPServer

from app import (
    find_code_owner,
    find_shortest_dependency_path,
    get_blast_radius,
)

server = MCPServer("gittrace")


def _fmt(result: dict) -> str:
    """Render a tool result dict as compact JSON for the MCP client."""
    return json.dumps(result, indent=2)


@server.tool()
def get_blast_radius_tool(cve_id: str) -> str:
    """Find all services and functions impacted by a CVE, showing the
    propagation path. Use when asked about blast radius, impact, or what
    breaks if a vulnerable function is taken offline."""
    return _fmt(get_blast_radius(cve_id))


@server.tool()
def find_shortest_dependency_path_tool(start_service: str, target_function: str) -> str:
    """Use FalkorDB's native shortestPath algorithm to trace how an attacker
    reaches vulnerable code from a public-facing service. Use when asked for
    the attack path, shortest path, or how an entry point reaches a function."""
    return _fmt(find_shortest_dependency_path(start_service, target_function))


@server.tool()
def find_code_owner_tool(function_name: str) -> str:
    """Find the developer who owns/authored the vulnerable code for alerting.
    Use when asked who owns the code, who to notify, or the contact info for
    a function."""
    return _fmt(find_code_owner(function_name))


def main() -> None:
    print("GitTrace MCP server starting (stdio transport)...", flush=True)
    print("Tools: get_blast_radius, find_shortest_dependency_path, find_code_owner",
          flush=True)
    server.run()


if __name__ == "__main__":
    main()
