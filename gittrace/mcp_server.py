"""
gittrace.mcp_server — GitTrace MCP server.

Exposes the graph tools over the Model Context Protocol (MCP) so any
MCP-capable agent host (Claude Desktop, custom agents, etc.) can query the
codebase dependency graph.

Tools are generated from gittrace.core.registry.TOOL_REGISTRY, one MCP tool per
entry, named "<tool>_tool" (e.g. get_blast_radius_tool). Each tool's input
schema comes from the graph function's own signature and its description from
the registry, so registering a tool there is all it takes to expose it here.

Run from the repository root (stdio transport, the standard for local MCP
servers):
    python -m gittrace.mcp_server

Then register this server in your MCP host with:
    { "command": "python", "args": ["-m", "gittrace.mcp_server"],
      "env": { "PYTHONPATH": "/path/to/GitTrace" } }

stdout is the protocol channel under stdio: nothing else may be printed to it.
"""

from __future__ import annotations

import inspect
import json
from typing import Any, Callable

from mcp.server.mcpserver import MCPServer

from gittrace.core.registry import TOOL_REGISTRY, GraphTool


def _fmt(result: dict) -> str:
    """Render a tool result dict as compact JSON for the MCP client."""
    return json.dumps(result, indent=2)


def mcp_tool_name(tool: GraphTool) -> str:
    return f"{tool.name}_tool"


def _handler(tool: GraphTool) -> Callable[..., str]:
    """Wrap a graph tool so it returns JSON text, keeping its signature.

    MCPServer builds the input schema from the handler's signature, so the
    wrapper advertises the graph function's parameters (with annotations
    evaluated, since gittrace.core.tools uses postponed annotations).
    """
    def handler(**kwargs: Any) -> str:
        return _fmt(tool.func(**kwargs))

    signature = inspect.signature(tool.func, eval_str=True)
    handler.__signature__ = signature.replace(return_annotation=str)  # type: ignore[attr-defined]
    handler.__name__ = mcp_tool_name(tool)
    handler.__doc__ = tool.description
    return handler


def build_server() -> MCPServer:
    server = MCPServer("gittrace")
    for tool in TOOL_REGISTRY.values():
        server.add_tool(
            _handler(tool),
            name=mcp_tool_name(tool),
            description=tool.description,
        )
    return server


server = build_server()


def main() -> None:
    from gittrace import config

    config.load()
    server.run()


if __name__ == "__main__":
    main()
