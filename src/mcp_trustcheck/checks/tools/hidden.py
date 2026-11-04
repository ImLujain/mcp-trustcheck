"""TOOL-002: hidden or obfuscated content in tool metadata (threat-model.md T1)."""

from __future__ import annotations

import re
import statistics
import unicodedata

from mcp_trustcheck.checks import Context, emit, register
from mcp_trustcheck.checks.tools.instructions import tool_strings
from mcp_trustcheck.model import Affected, Confidence, Finding, Severity, ToolSet

INVISIBLE = {
    "​": "ZERO WIDTH SPACE",
    "‌": "ZERO WIDTH NON-JOINER",
    "‍": "ZERO WIDTH JOINER",
    "⁠": "WORD JOINER",
    "﻿": "ZERO WIDTH NO-BREAK SPACE",
    "­": "SOFT HYPHEN",
    "᠎": "MONGOLIAN VOWEL SEPARATOR",
    "⁡": "FUNCTION APPLICATION",
    "⁢": "INVISIBLE TIMES",
    "⁣": "INVISIBLE SEPARATOR",
    "⁤": "INVISIBLE PLUS",
}
BIDI = {"‪", "‫", "‬", "‭", "‮", "⁦", "⁧", "⁨", "⁩", "‎", "‏", "؜"}
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
_B64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{64,}={0,2}(?![A-Za-z0-9+/])")
_HEX_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){32,}(?![0-9A-Fa-f])")
_WS_RUN_RE = re.compile(r"[ \t\u00a0]{100,}|\n{25,}")
OUTLIER_FACTOR = 5
OUTLIER_MIN = 2000


def _code_point_issues(text: str) -> list[str]:
    issues: list[str] = []
    for ch in set(text):
        if ch in INVISIBLE:
            issues.append(f"U+{ord(ch):04X} {INVISIBLE[ch]}")
        elif ch in BIDI:
            issues.append(f"U+{ord(ch):04X} {unicodedata.name(ch, 'BIDI CONTROL')}")
        elif 0xE0000 <= ord(ch) <= 0xE007F:
            issues.append(f"U+{ord(ch):05X} TAG CHARACTER (Unicode tags block)")
        elif unicodedata.category(ch) == "Cf" and ch not in ("‍",):
            issues.append(f"U+{ord(ch):04X} {unicodedata.name(ch, 'FORMAT CHARACTER')}")
    return sorted(set(issues))


@register("TOOL-002", "tools")
def check_hidden_content(toolset: ToolSet, ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    lengths = [len(t.description or "") for t in toolset.tools]
    median = statistics.median(lengths) if lengths else 0
    for tool in toolset.tools:
        evidence: list[tuple[str, str, str | None]] = []
        conf = Confidence.MEDIUM
        for path, text in tool_strings(tool):
            cps = _code_point_issues(text)
            if cps:
                conf = Confidence.HIGH
                visible = text.encode("unicode_escape").decode("ascii")
                evidence.append(
                    (path, visible, "invisible/bidi code points: " + ", ".join(cps[:4]))
                )
            for m in _HTML_COMMENT_RE.finditer(text):
                conf = Confidence.HIGH
                evidence.append((path, m.group(0), "HTML comment hidden from most renderers"))
            if _B64_RE.search(text):
                evidence.append((path, _B64_RE.search(text).group(0)[:80], "long base64-like run"))  # type: ignore[union-attr]
            if _HEX_RE.search(text):
                evidence.append((path, _HEX_RE.search(text).group(0)[:80], "long hex run"))  # type: ignore[union-attr]
            if _WS_RUN_RE.search(text):
                evidence.append(
                    (
                        path,
                        "(whitespace run)",
                        "≥100 spaces or ≥25 blank lines: padding pushes content out of view",
                    )
                )
        dl = len(tool.description or "")
        if median and dl > OUTLIER_MIN and dl > OUTLIER_FACTOR * median:
            evidence.append(
                (
                    f"{tool.json_path}.description",
                    f"{dl} chars",
                    f"description is {dl / median:.0f}x the catalogue median ({median:.0f})",
                )
            )
        if not evidence:
            continue
        findings.append(
            emit(
                ctx,
                "TOOL-002",
                affected=Affected(
                    tool.source_file, tool.json_path, server=toolset.server_label, tool=tool.name
                ),
                evidence=evidence[:6],
                description=f"Tool '{tool.name}' contains content a reviewer is unlikely to see as rendered: "
                + "; ".join(sorted({e[2] or "" for e in evidence}))[:300]
                + ".",
                severity=Severity.MEDIUM,
                confidence=conf,
            )
        )
    return findings
