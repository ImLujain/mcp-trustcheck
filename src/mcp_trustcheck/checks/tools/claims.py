"""TOOL-012: a tool's catalogue entry versus what its handler's code can reach (threat-model.md T1).

The catalogue is matched to a package manifest by server label. For each tool with an attributed
handler, the capability classes reachable from the handler are compared with what the catalogue
claims: the `readOnlyHint` annotation first, then the name/description vocabulary the existing
TOOL-004 heuristics already use. Only contradictions are reported; a tool that says it writes and
does write is fine.
"""

from __future__ import annotations

from mcp_trustcheck.checks import Context, emit, register
from mcp_trustcheck.checks.tools._capability import INGRESS_VERB_RE, infer, tokens
from mcp_trustcheck.code.model import (
    PHRASES,
    SIDE_EFFECT_CLASSES,
    PackageManifest,
    ToolCapabilities,
)
from mcp_trustcheck.model import (
    Affected,
    Confidence,
    Finding,
    Kind,
    Severity,
    ToolDefinition,
    ToolSet,
)

_READ_VERBS = INGRESS_VERB_RE


def _looks_read_only(tool: ToolDefinition) -> bool:
    classes, _ = infer(tool)
    if classes:
        return False
    toks = tokens(tool.name)
    return any(_READ_VERBS.match(t) for t in toks)


def _confidence(manifest: PackageManifest, tc: ToolCapabilities) -> Confidence:
    if any("minified" in n for n in manifest.notes):
        return Confidence.LOW
    return Confidence.HIGH if manifest.attribution == "ast" else Confidence.MEDIUM


def _evidence(
    tc: ToolCapabilities, classes: set[str], tool_path: str
) -> list[tuple[str, str, str | None]]:
    out: list[tuple[str, str, str | None]] = []
    for s in tc.sinks:
        if s.cls in classes and len(out) < 4:
            where = f"{s.file}:{s.line}"
            out.append(
                (tool_path, f"{where} {s.snippet or s.callee}", f"{PHRASES[s.cls]} via {s.callee}")
            )
    return out


@register("TOOL-012", "tools")
def check_claims_vs_code(toolset: ToolSet, ctx: Context) -> list[Finding]:
    manifest = ctx.manifest_for_label(toolset.server_label)
    if manifest is None or manifest.attribution == "none":
        return []
    findings: list[Finding] = []
    for tool in toolset.tools:
        tc = manifest.tools.get(tool.name)
        if tc is None or not tc.handler:
            continue
        code = tc.classes
        side = code & SIDE_EFFECT_CLASSES
        if not side:
            continue
        conf = _confidence(manifest, tc)
        affected = Affected(
            tool.source_file, tool.json_path, server=toolset.server_label, tool=tool.name
        )
        handler = f"{manifest.root}/{tc.handler}"
        can = ", ".join(PHRASES[c] for c in sorted(side))

        if tool.annotations.get("readOnlyHint") is True:
            findings.append(
                emit(
                    ctx,
                    "TOOL-012",
                    affected=affected,
                    evidence=[
                        (
                            f"{tool.json_path}.annotations.readOnlyHint",
                            "true",
                            "declared read-only",
                        ),
                        *_evidence(tc, side, tool.json_path),
                    ],
                    description=f"Tool '{tool.name}' is annotated `readOnlyHint: true`, but its handler ({handler}) "
                    f"can {can}.",
                    severity=Severity.HIGH,
                    confidence=conf,
                    kind=Kind.WEAKNESS,
                    key="readonly",
                )
            )
            continue
        if not _looks_read_only(tool):
            continue
        strong = side & {"exec", "fs_delete"}
        if strong:
            sev, key = Severity.MEDIUM, "lookalike"
        else:
            sev, key = Severity.LOW, "writes"
        findings.append(
            emit(
                ctx,
                "TOOL-012",
                affected=affected,
                evidence=[
                    (f"{tool.json_path}.name", tool.name, "read-only vocabulary"),
                    *_evidence(tc, side, tool.json_path),
                ],
                description=f"Tool '{tool.name}' reads like a read-only operation, but its handler ({handler}) "
                f"can {can}. The catalogue entry gives a user no reason to expect that.",
                severity=sev,
                confidence=conf
                if strong
                else Confidence.LOW
                if conf == Confidence.LOW
                else Confidence.MEDIUM,
                kind=Kind.INDICATOR,
                key=key,
            )
        )
    return findings
