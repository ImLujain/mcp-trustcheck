"""TOOL-007: tool name collisions and look-alikes across catalogues (threat-model.md T3)."""

from __future__ import annotations

import re
import unicodedata

from mcp_trustcheck.checks import Context, emit, register
from mcp_trustcheck.model import Affected, Confidence, Finding, Severity, ToolDefinition, ToolSet

_CONFUSABLES = str.maketrans(
    {
        # digits / symbols commonly used as letter stand-ins
        "0": "o",
        "1": "l",
        "3": "e",
        "5": "s",
        "7": "t",
        "8": "b",
        "$": "s",
        "@": "a",
        "!": "i",
        "|": "l",
        # Cyrillic homoglyphs of Latin letters, written as escapes so the mapping stays reviewable
        "\u0430": "a",
        "\u0435": "e",
        "\u043e": "o",
        "\u0440": "p",
        "\u0441": "c",
        "\u0445": "x",
        "\u0443": "y",
        "\u0456": "i",
        "\u0455": "s",
        "\u0458": "j",
    }
)


def normalise(name: str) -> str:
    n = unicodedata.normalize("NFKC", name).lower().translate(_CONFUSABLES)
    return re.sub(r"[^a-z0-9]", "", n)


@register("TOOL-007", "tools")
def check_name_collisions(toolset: ToolSet, ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    # Within one catalogue: exact duplicates (spec: SHOULD be unique within a server).
    seen: dict[str, ToolDefinition] = {}
    for t in toolset.tools:
        if t.name in seen:
            findings.append(
                emit(
                    ctx,
                    "TOOL-007",
                    affected=Affected(
                        t.source_file, t.json_path, server=toolset.server_label, tool=t.name
                    ),
                    evidence=[
                        (seen[t.name].json_path, t.name, "first"),
                        (t.json_path, t.name, "duplicate"),
                    ],
                    description=f"Tool name '{t.name}' is defined twice in catalogue '{toolset.server_label}'.",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    key="within",
                )
            )
        else:
            seen[t.name] = t

    # Across catalogues with different server labels.
    index: dict[str, list[tuple[str, ToolDefinition]]] = ctx.state.setdefault("tool007", {})
    for t in toolset.tools:
        key = normalise(t.name)
        for other_label, other in index.get(key, []):
            if other_label == toolset.server_label:
                continue
            exact = other.name == t.name
            findings.append(
                emit(
                    ctx,
                    "TOOL-007",
                    affected=Affected(
                        t.source_file, t.json_path, server=toolset.server_label, tool=t.name
                    ),
                    evidence=[
                        (
                            other.json_path,
                            other.name,
                            f"server '{other_label}' ({other.source_file})",
                        ),
                        (t.json_path, t.name, f"server '{toolset.server_label}'"),
                    ],
                    description=(
                        f"Tool '{t.name}' is exposed by both '{other_label}' and '{toolset.server_label}'."
                        if exact
                        else f"Tool '{t.name}' in '{toolset.server_label}' is a look-alike of '{other.name}' in '{other_label}'."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH if exact else Confidence.MEDIUM,
                    key=f"{other_label}:{other.name}",
                )
            )
        index.setdefault(key, []).append((toolset.server_label, t))
    return findings
