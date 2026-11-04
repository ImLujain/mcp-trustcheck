"""CFG-014: duplicate server definitions within one file (threat-model.md T3)."""

from __future__ import annotations

from mcp_trustcheck.checks import Context, emit, register
from mcp_trustcheck.model import Affected, Finding, ServerConfig


def _target(server: ServerConfig) -> str | None:
    if server.url is not None:
        return "url:" + server.url.value.rstrip("/")
    if server.command:
        return "cmd:" + server.command_line
    return None


@register("CFG-014", "config")
def check_duplicate_servers(server: ServerConfig, ctx: Context) -> list[Finding]:
    target = _target(server)
    if target is None:
        return []
    seen: dict[tuple[str, str], ServerConfig] = ctx.state.setdefault("cfg014", {})
    key = (server.source_file, target)
    first = seen.get(key)
    if first is None:
        seen[key] = server
        return []
    return [
        emit(
            ctx,
            "CFG-014",
            affected=Affected(server.source_file, server.json_path, server=server.name),
            evidence=[
                (first.json_path, target.split(":", 1)[1], f"first definition: '{first.name}'"),
                (server.json_path, target.split(":", 1)[1], f"duplicate: '{server.name}'"),
            ],
            description=f"Servers '{first.name}' and '{server.name}' in the same file launch the same target.",
        )
    ]
