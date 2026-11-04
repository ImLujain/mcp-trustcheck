"""Tool catalogue shapes (docs/design.md §2.3)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mcp_trustcheck.loaders.config import jkey
from mcp_trustcheck.model import ToolDefinition, ToolSet

SERVER_INFO_KEY = "io.modelcontextprotocol/serverInfo"


def _server_label(obj: Any, source: str) -> str:
    if isinstance(obj, dict):
        for candidate in (obj.get("server"), obj.get("serverName")):
            if isinstance(candidate, str) and candidate.strip():
                return candidate.strip()
        for meta_holder in (
            obj,
            obj.get("result") if isinstance(obj.get("result"), dict) else None,
        ):
            if isinstance(meta_holder, dict):
                meta = meta_holder.get("_meta")
                if isinstance(meta, dict):
                    info = meta.get(SERVER_INFO_KEY)
                    if isinstance(info, dict):
                        name = info.get("name")
                        if isinstance(name, str) and name.strip():
                            return name
    return Path(source).stem


def load_toolset(obj: Any, shape: str, source: str) -> ToolSet:
    if shape == "jsonrpc-result":
        tools_raw, base = obj["result"]["tools"], "$.result.tools"
    elif shape == "tools-object":
        tools_raw, base = obj["tools"], "$.tools"
    elif shape == "array":
        tools_raw, base = obj, "$"
    else:  # pragma: no cover
        raise ValueError(f"unknown tools shape {shape}")

    label = _server_label(obj, source)
    ts = ToolSet(source_file=source, server_label=label, shape=shape)
    for i, t in enumerate(tools_raw):
        if not isinstance(t, dict) or not isinstance(t.get("name"), str):
            continue
        ann = t.get("annotations")
        ts.tools.append(
            ToolDefinition(
                name=t["name"],
                source_file=source,
                json_path=f"{base}[{i}]",
                server_label=label,
                title=t.get("title") if isinstance(t.get("title"), str) else None,
                description=t.get("description") if isinstance(t.get("description"), str) else None,
                input_schema=t.get("inputSchema")
                if isinstance(t.get("inputSchema"), dict)
                else None,
                output_schema=t.get("outputSchema")
                if isinstance(t.get("outputSchema"), dict)
                else None,
                annotations=ann if isinstance(ann, dict) else {},
                raw=t,
            )
        )
    return ts


__all__ = ["jkey", "load_toolset"]
