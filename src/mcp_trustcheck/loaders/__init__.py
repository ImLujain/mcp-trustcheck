"""Loaders turn parsed JSON into ServerConfig / ToolDefinition objects.

`detect_kind` is structural: it looks at the shape of the JSON, never at the filename.
"""

from __future__ import annotations

from typing import Any


def _looks_like_server(v: Any) -> bool:
    return isinstance(v, dict) and any(k in v for k in ("command", "url", "type", "transport"))


def _looks_like_tool(t: Any) -> bool:
    return (
        isinstance(t, dict)
        and isinstance(t.get("name"), str)
        and any(k in t for k in ("inputSchema", "description", "annotations", "title"))
    )


def detect_kind(obj: Any) -> tuple[str, str] | None:
    """Return (kind, dialect) or None. kind is "config" or "tools"."""
    if isinstance(obj, dict):
        if isinstance(obj.get("mcpServers"), dict):
            return ("config", "mcpServers")
        mcp = obj.get("mcp")
        if isinstance(mcp, dict) and isinstance(mcp.get("servers"), dict):
            return ("config", "vscode-settings")
        servers = obj.get("servers")
        if isinstance(servers, dict) and (
            not servers or any(_looks_like_server(v) for v in servers.values())
        ):
            return ("config", "vscode")
        result = obj.get("result")
        if isinstance(result, dict) and isinstance(result.get("tools"), list):
            return ("tools", "jsonrpc-result")
        if isinstance(obj.get("tools"), list):
            return ("tools", "tools-object")
        return None
    if isinstance(obj, list) and obj and all(_looks_like_tool(t) for t in obj):
        return ("tools", "array")
    return None
