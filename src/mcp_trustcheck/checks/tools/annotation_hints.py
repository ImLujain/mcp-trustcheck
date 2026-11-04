"""TOOL-004: annotation contradicts apparent capability (threat-model.md T1/T5)."""

from __future__ import annotations

from mcp_trustcheck.checks import Context, emit, register
from mcp_trustcheck.checks.tools._capability import infer
from mcp_trustcheck.model import Affected, Confidence, Finding, Kind, Severity, ToolSet


@register("TOOL-004", "tools")
def check_annotation_mismatch(toolset: ToolSet, ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    for tool in toolset.tools:
        classes, basis = infer(tool)
        if not classes:
            continue
        ann = tool.annotations
        conf = Confidence.MEDIUM if basis == "name" else Confidence.LOW
        caps = ", ".join(sorted(classes))
        affected = Affected(
            tool.source_file,
            f"{tool.json_path}.annotations",
            server=toolset.server_label,
            tool=tool.name,
        )
        if ann.get("readOnlyHint") is True:
            findings.append(
                emit(
                    ctx,
                    "TOOL-004",
                    affected=affected,
                    evidence=[
                        (
                            f"{tool.json_path}.annotations.readOnlyHint",
                            "true",
                            f"apparent capability from {basis}: {caps}",
                        )
                    ],
                    description=f"Tool '{tool.name}' is annotated readOnlyHint=true but its {basis} suggests it "
                    f"performs {caps} operations.",
                    severity=Severity.MEDIUM,
                    confidence=conf,
                    key="readonly",
                )
            )
        elif ann.get("destructiveHint") is False and classes & {"delete", "exec"}:
            findings.append(
                emit(
                    ctx,
                    "TOOL-004",
                    affected=affected,
                    evidence=[
                        (
                            f"{tool.json_path}.annotations.destructiveHint",
                            "false",
                            f"apparent capability from {basis}: {caps}",
                        )
                    ],
                    description=f"Tool '{tool.name}' is annotated destructiveHint=false but its {basis} suggests "
                    f"{caps} operations.",
                    severity=Severity.MEDIUM,
                    confidence=conf,
                    key="destructive",
                )
            )
        elif not ann and classes & {"exec", "delete", "send"}:
            findings.append(
                emit(
                    ctx,
                    "TOOL-004",
                    affected=affected,
                    evidence=[
                        (
                            tool.json_path,
                            tool.name,
                            f"no annotations; apparent capability from {basis}: {caps}",
                        )
                    ],
                    description=f"Tool '{tool.name}' appears to perform {caps} operations and carries no annotations; "
                    "clients must treat it as destructive and open-world.",
                    severity=Severity.INFO,
                    confidence=conf,
                    kind=Kind.INFO,
                    key="missing",
                )
            )
    return findings
