"""TOOL-008: untrusted-content ingress and side-effect sinks in one catalogue (threat-model.md T4)."""

from __future__ import annotations

from mcp_trustcheck.checks import Context, emit, register
from mcp_trustcheck.checks.tools._capability import infer, is_ingress
from mcp_trustcheck.model import Affected, Confidence, Finding, ToolSet


@register("TOOL-008", "tools")
def check_ingress_surface(toolset: ToolSet, ctx: Context) -> list[Finding]:
    ingress: list[tuple[str, str, str | None]] = []
    sinks: list[tuple[str, str, str | None]] = []
    basis_conf = Confidence.LOW
    for t in toolset.tools:
        ing, basis = is_ingress(t)
        if ing:
            ingress.append((t.json_path, t.name, f"ingress ({basis})"))
            if basis == "annotation":
                basis_conf = Confidence.HIGH
            elif basis_conf is Confidence.LOW:
                basis_conf = Confidence.MEDIUM
        caps, cbasis = infer(t)
        if caps & {"exec", "write", "delete", "send"}:
            sinks.append((t.json_path, t.name, f"sink: {', '.join(sorted(caps))} ({cbasis})"))
    if not ingress:
        return []
    chain = (
        " Combined with side-effect tools in the same catalogue, retrieved content can become actions."
        if sinks
        else ""
    )
    return [
        emit(
            ctx,
            "TOOL-008",
            affected=Affected(toolset.source_file, "$", server=toolset.server_label),
            evidence=(ingress + sinks)[:10],
            description=f"Catalogue '{toolset.server_label}' exposes {len(ingress)} tool(s) that import external "
            f"content and {len(sinks)} tool(s) with side effects.{chain}",
            confidence=basis_conf,
        )
    ]
