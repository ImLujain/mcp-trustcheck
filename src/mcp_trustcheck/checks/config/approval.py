"""CFG-013: tool approval bypassed via client auto-approve/trust keys (threat-model.md T11)."""

from __future__ import annotations

import json

from mcp_trustcheck.checks import Context, emit, register
from mcp_trustcheck.model import Affected, Finding, ServerConfig, Severity

_APPROVAL_KEYS = ("autoApprove", "alwaysAllow", "trust")


@register("CFG-013", "config")
def check_auto_approval(server: ServerConfig, ctx: Context) -> list[Finding]:
    if server.disabled:
        return []
    wildcard = server.auto_approve_all or server.trust is True
    if not wildcard and not server.auto_approve:
        return []
    present = [k for k in _APPROVAL_KEYS if k in server.raw]
    evidence = [(f"{server.json_path}.{k}", _fmt(server.raw[k])) for k in present]
    if wildcard:
        desc = (
            f"Server '{server.name}' is configured so that every tool it exposes — including tools added "
            "later — runs without a confirmation prompt."
        )
        sev = Severity.HIGH
    else:
        names = ", ".join(server.auto_approve[:8]) + (" …" if len(server.auto_approve) > 8 else "")
        desc = (
            f"Server '{server.name}' auto-approves {len(server.auto_approve)} tool(s) without a "
            f"confirmation prompt: {names}."
        )
        sev = Severity.MEDIUM
    return [
        emit(
            ctx,
            "CFG-013",
            affected=Affected(server.source_file, server.json_path, server=server.name),
            evidence=evidence,
            description=desc,
            severity=sev,
        )
    ]


def _fmt(v: object) -> str:
    return json.dumps(v, ensure_ascii=False)
