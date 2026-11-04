"""TOOL-006: tool definition drift against an approved baseline (threat-model.md T2)."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from typing import Any

from mcp_trustcheck.checks import Context, emit, register
from mcp_trustcheck.model import (
    Affected,
    Confidence,
    Finding,
    Kind,
    Severity,
    ToolDefinition,
    ToolSet,
)

CANON_FIELDS = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")


def _nfc(obj: Any) -> Any:
    if isinstance(obj, str):
        return unicodedata.normalize("NFC", obj)
    if isinstance(obj, dict):
        return {_nfc(k): _nfc(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_nfc(v) for v in obj]
    return obj


def canonical(tool: ToolDefinition) -> str:
    subset = {k: tool.raw[k] for k in CANON_FIELDS if k in tool.raw}
    return json.dumps(_nfc(subset), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(tool: ToolDefinition) -> str:
    return hashlib.sha256(canonical(tool).encode("utf-8")).hexdigest()


def _changed_fields(old: ToolDefinition, new: ToolDefinition) -> list[str]:
    return [f for f in CANON_FIELDS if _nfc(old.raw.get(f)) != _nfc(new.raw.get(f))]


def _first_diff(a: str, b: str, width: int = 50) -> str:
    i = 0
    while i < min(len(a), len(b)) and a[i] == b[i]:
        i += 1
    start = max(0, i - 20)
    return f"…{a[start : start + width]!r} → …{b[start : start + width]!r}"


@register("TOOL-006", "tools")
def check_baseline_drift(toolset: ToolSet, ctx: Context) -> list[Finding]:
    if ctx.baseline is None:
        return []
    base = {t.name: t for t in ctx.baseline.tools}
    cur = {t.name: t for t in toolset.tools}
    findings: list[Finding] = []
    baseline_note = f"baseline: {ctx.baseline_path}" if ctx.baseline_path else "baseline"

    for name, tool in cur.items():
        old = base.get(name)
        if old is None:
            findings.append(
                emit(
                    ctx,
                    "TOOL-006",
                    affected=Affected(
                        tool.source_file, tool.json_path, server=toolset.server_label, tool=name
                    ),
                    evidence=[(f"{tool.json_path}.name", name, f"not present in {baseline_note}")],
                    description=f"Tool '{name}' was not in the approved baseline; it has been added since review.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    key="added",
                )
            )
            continue
        if digest(old) == digest(tool):
            continue
        fields = _changed_fields(old, tool)
        evidence: list[tuple[str, str, str | None]] = []
        for f in fields:
            o, n = old.raw.get(f), tool.raw.get(f)
            if isinstance(o, str) and isinstance(n, str):
                evidence.append((f"{tool.json_path}.{f}", _first_diff(o, n), f"{f} changed"))
            else:
                evidence.append(
                    (
                        f"{tool.json_path}.{f}",
                        json.dumps(n, ensure_ascii=False)[:200],
                        f"{f} changed",
                    )
                )
        findings.append(
            emit(
                ctx,
                "TOOL-006",
                affected=Affected(
                    tool.source_file, tool.json_path, server=toolset.server_label, tool=name
                ),
                evidence=evidence,
                description=f"Tool '{name}' differs from the approved baseline in: {', '.join(fields)}. "
                f"(sha256 {digest(old)[:12]} → {digest(tool)[:12]})",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                key="changed",
            )
        )

    for name in base:
        if name not in cur:
            findings.append(
                emit(
                    ctx,
                    "TOOL-006",
                    affected=Affected(
                        toolset.source_file, "$", server=toolset.server_label, tool=name
                    ),
                    evidence=[("$", name, f"present in {baseline_note}, absent now")],
                    description=f"Tool '{name}' from the approved baseline is no longer offered.",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    kind=Kind.INFO,
                    key=f"removed:{name}",
                )
            )
    return findings
