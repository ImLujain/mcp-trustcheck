"""Client config dialects (docs/design.md §2.2).

Understood: the `mcpServers` family (Claude Desktop, Claude Code `.mcp.json`, Cursor, Windsurf,
Cline/Roo, Gemini CLI …) and VS Code `servers` + `inputs` (standalone `mcp.json` or inside
`settings.json` under `mcp`). Unknown keys are preserved in `raw` and listed in `unparsed_keys`.
"""

from __future__ import annotations

from typing import Any

from mcp_trustcheck.loaders.refs import is_literal
from mcp_trustcheck.model import ConfigValue, ServerConfig

KNOWN_KEYS = frozenset(
    {
        "command",
        "args",
        "env",
        "url",
        "headers",
        "requestInit",
        "type",
        "transport",
        "cwd",
        "autoApprove",
        "alwaysAllow",
        "trust",
        "disabled",
        "enabled",
        "timeout",
        "envFile",
        "description",
        "name",
    }
)

_HTTP_TYPES = {"http", "streamable-http", "streamablehttp", "streamable_http", "remote"}
_SSE_TYPES = {"sse"}


def jkey(key: str) -> str:
    """Format a dict key for a JSONPath-style string."""
    if key.isidentifier():
        return f".{key}"
    return "[" + '"' + key.replace("\\", "\\\\").replace('"', '\\"') + '"' + "]"


def _cv(value: Any, path: str) -> ConfigValue:
    s = value if isinstance(value, str) else str(value)
    return ConfigValue(value=s, literal=is_literal(s), json_path=path)


def _str_dict(obj: Any, base: str) -> dict[str, ConfigValue]:
    if not isinstance(obj, dict):
        return {}
    return {str(k): _cv(v, f"{base}{jkey(str(k))}") for k, v in obj.items() if v is not None}


def _infer_transport(entry: dict[str, Any]) -> str:
    t = entry.get("type") or entry.get("transport")
    if isinstance(t, str):
        tl = t.lower()
        if tl in _SSE_TYPES:
            return "sse"
        if tl in _HTTP_TYPES:
            return "http"
        if tl == "stdio":
            return "stdio"
    url = entry.get("url")
    if isinstance(url, str) and url:
        return "sse" if url.rstrip("/").endswith("/sse") else "http"
    if isinstance(entry.get("command"), str):
        return "stdio"
    return "unknown"


def _parse_server(
    name: str, entry: dict[str, Any], base: str, source: str, dialect: str
) -> ServerConfig:
    args_raw = entry.get("args")
    args: list[ConfigValue] = []
    if isinstance(args_raw, list):
        args = [_cv(a, f"{base}.args[{i}]") for i, a in enumerate(args_raw) if a is not None]

    headers = _str_dict(entry.get("headers"), f"{base}.headers")
    req_init = entry.get("requestInit")
    if not headers and isinstance(req_init, dict):
        headers = _str_dict(req_init.get("headers"), f"{base}.requestInit.headers")

    url_raw = entry.get("url")
    url = _cv(url_raw, f"{base}.url") if isinstance(url_raw, str) and url_raw else None

    auto: list[str] = []
    auto_all = False
    for key in ("autoApprove", "alwaysAllow"):
        v = entry.get(key)
        if v is True:
            auto_all = True
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, str):
                    if item.strip() == "*":
                        auto_all = True
                    else:
                        auto.append(item)
    trust = entry.get("trust") if isinstance(entry.get("trust"), bool) else None
    disabled = entry.get("disabled") is True or entry.get("enabled") is False

    command = entry.get("command")
    return ServerConfig(
        name=name,
        source_file=source,
        json_path=base,
        dialect=dialect,
        transport=_infer_transport(entry),
        command=command if isinstance(command, str) and command else None,
        args=args,
        env=_str_dict(entry.get("env"), f"{base}.env"),
        url=url,
        headers=headers,
        auto_approve=auto,
        auto_approve_all=auto_all,
        trust=trust,
        disabled=disabled,
        unparsed_keys=sorted(k for k in entry if k not in KNOWN_KEYS),
        raw=entry,
    )


def load_servers(obj: dict[str, Any], dialect: str, source: str) -> list[ServerConfig]:
    if dialect == "mcpServers":
        container, base = obj["mcpServers"], "$.mcpServers"
    elif dialect == "vscode":
        container, base = obj["servers"], "$.servers"
    elif dialect == "vscode-settings":
        container, base = obj["mcp"]["servers"], "$.mcp.servers"
    else:  # pragma: no cover - detect_kind only yields the above
        raise ValueError(f"unknown config dialect {dialect}")

    servers: list[ServerConfig] = []
    for name, entry in container.items():
        if not isinstance(entry, dict):
            continue  # malformed entry; tolerated, counted nowhere
        servers.append(_parse_server(str(name), entry, f"{base}{jkey(str(name))}", source, dialect))
    return servers
