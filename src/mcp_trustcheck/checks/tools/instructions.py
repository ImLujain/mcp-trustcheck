"""TOOL-001: agent-directed instructions in tool metadata (threat-model.md T1).

Six signal classes are matched across every string in a tool definition. This is a lexical
indicator for human review; it never asserts that a tool is malicious.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from mcp_trustcheck.checks import Context, emit, register
from mcp_trustcheck.loaders.config import jkey
from mcp_trustcheck.model import Affected, Confidence, Finding, Severity, ToolDefinition, ToolSet

SIGNALS: dict[str, tuple[str, re.Pattern[str]]] = {
    "S1": (
        "model-directed imperative",
        re.compile(
            r"(?i)\b(?:you\s+(?:must|should|need\s+to|have\s+to|are\s+(?:required|instructed|expected)\s+to)"
            r"|(?:before|after|prior\s+to)\s+(?:calling|invoking|using|running|executing)\s+(?:this|the|any|another|other|each)"
            r"|(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|the\s+|your\s+)?(?:previous|prior|above|earlier|system|safety|other)\s+(?:instructions?|rules?|guidelines?|prompts?|constraints?)"
            r"|\b(?:system\s+prompt|developer\s+message|hidden\s+instructions?)\b"
            r"|\bthis\s+is\s+(?:very\s+)?important\s+(?:for|to)\s+(?:the\s+)?(?:tool|function|model)\b)"
        ),
    ),
    "S2": (
        "concealment from the user",
        re.compile(
            r"(?i)(?:\b(?:do\s+not|don'?t|never|without)\s+(?:tell(?:ing)?|mention(?:ing)?|inform(?:ing)?|reveal(?:ing)?|show(?:ing)?|disclos(?:e|ing)|notify(?:ing)?|alert(?:ing)?|explain(?:ing)?\s+(?:this\s+)?to)\b[^.]{0,90}\b(?:user|human|them|anyone)\b"
            r"|\b(?:silently|secretly|covertly|discreetly|quietly)\b"
            r"|\b(?:hidden|invisible|not\s+visible)\s+(?:from|to)\s+the\s+user\b"
            r"|\bthe\s+user\s+(?:should|must|will|does)\s+not\s+(?:see|know|notice|be\s+(?:aware|told|informed))\b"
            r"|\bkeep\s+(?:this|it)\s+(?:a\s+)?(?:secret|hidden|confidential|between)\b)"
        ),
    ),
    "S3": (
        "pseudo system tag",
        re.compile(
            r"(?i)(?:<\s*/?\s*(?:important|system|instructions?|admin|hidden|secret|override|critical|note\s+to\s+(?:ai|model|assistant|llm))\b[^>]*>"
            r"|\[\s*(?:system|important|admin|hidden|secret|override|ai\s+only)\s*\]"
            r"|#{2,}\s*(?:system|important|hidden)\b"
            r"|\bbegin\s+(?:hidden|secret|system)\b)"
        ),
    ),
    "S4": (
        "sensitive file or credential reference",
        re.compile(
            r"(?i)(?:~?/?\.ssh\b|\bid_(?:rsa|ed25519|ecdsa)\b|\.aws/credentials|\.aws\b|\bauthorized_keys\b"
            r"|/etc/(?:passwd|shadow)|\.npmrc\b|\.netrc\b|\.git-credentials\b|\.bash_history\b|\.zsh_history\b"
            r"|\bkeychain\b|\.kube/config|\.env\b|\bmcp\.json\b|claude_desktop_config|\.cursor/|\.gnupg\b"
            r"|\b(?:api[-_ ]?keys?|access[-_ ]?tokens?|private[-_ ]?keys?|passwords?|credentials?|secrets?)\s+(?:stored|saved|found|located|from)\b)"
        ),
    ),
    "S5": (
        "exfiltration channel or hidden parameter",
        re.compile(
            r"(?i)(?:\b(?:send|post|forward|upload|transmit|submit|exfiltrate|email|report)\b[^.]{0,80}\b(?:to|via)\s+(?:https?://|the\s+(?:url|endpoint|server|webhook|address)|[\w.-]+@[\w.-]+)"
            r"|\b(?:pass|include|append|add|put|place|insert|embed|encode)\b[^.]{0,80}\b(?:contents?|value|data|result|output|text)\b[^.]{0,60}\b(?:as|in|into|inside|within)\s+(?:the\s+|a\s+|an\s+)?(?:\w+\s+){0,2}(?:parameter|argument|field|sidenote|side\s+note|comment|note|metadata)\b"
            r"|\bside[-\s]?note\b)"
        ),
    ),
    "S6": (
        "cross-tool manipulation",
        re.compile(
            r"(?i)(?:\b(?:when|whenever|if|every\s+time|each\s+time)\s+(?:the\s+user|you|the\s+model|the\s+assistant)\s+(?:uses?|calls?|invokes?|runs?)\s+(?:the\s+)?(?:[\w.-]+\s+)?tool\b"
            r"|\b(?:all|every|any)\s+(?:other\s+)?tools?\b[^.]{0,80}\b(?:must|should|instead|replace|change|redirect)\b"
            r"|\b(?:change|replace|modify|redirect|substitute|swap|set)\s+(?:the\s+)?(?:recipient|email\s+address|to\s+address|destination|target\s+url|url|account(?:\s+number)?|wallet|iban|phone\s+number)\b"
            r"|\bthis\s+tool\s+(?:takes|has)\s+precedence\b|\boverrides?\s+(?:the\s+)?(?:behaviou?r|output|results?)\s+of\b)"
        ),
    ),
}

_TEXT_KEYS = ("description", "title", "default", "const", "summary", "x-description")
_LIST_TEXT_KEYS = ("enum", "examples")


def iter_strings(obj: Any, path: str) -> Iterator[tuple[str, str]]:
    """Yield (json_path, text) for every human-readable string inside a schema-like object."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{path}{jkey(str(k))}"
            if k in _TEXT_KEYS and isinstance(v, str):
                yield (p, v)
            elif k in _LIST_TEXT_KEYS and isinstance(v, list):
                for i, item in enumerate(v):
                    if isinstance(item, str):
                        yield (f"{p}[{i}]", item)
            elif isinstance(v, (dict, list)):
                yield from iter_strings(v, p)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            yield from iter_strings(item, f"{path}[{i}]")


def tool_strings(tool: ToolDefinition) -> Iterator[tuple[str, str]]:
    base = tool.json_path
    if tool.description:
        yield (f"{base}.description", tool.description)
    if tool.title:
        yield (f"{base}.title", tool.title)
    if tool.input_schema:
        yield from iter_strings(tool.input_schema, f"{base}.inputSchema")
    if tool.output_schema:
        yield from iter_strings(tool.output_schema, f"{base}.outputSchema")
    if tool.annotations:
        yield from iter_strings(tool.annotations, f"{base}.annotations")


def _context(text: str, start: int, end: int, width: int = 60) -> str:
    a, b = max(0, start - width), min(len(text), end + width)
    return ("…" if a > 0 else "") + text[a:b] + ("…" if b < len(text) else "")


def analyse(tool: ToolDefinition) -> tuple[set[str], list[tuple[str, str, str | None]]]:
    classes: set[str] = set()
    evidence: list[tuple[str, str, str | None]] = []
    for path, text in tool_strings(tool):
        for sid, (label, rx) in SIGNALS.items():
            m = rx.search(text)
            if m:
                classes.add(sid)
                evidence.append((path, _context(text, m.start(), m.end()), f"{sid}: {label}"))
    return classes, evidence


def grade(classes: set[str]) -> tuple[Severity, Confidence]:
    n = len(classes)
    if ("S2" in classes and classes & {"S4", "S5", "S6"}) or {"S4", "S5"} <= classes:
        sev = Severity.HIGH
    elif n >= 2 or "S2" in classes or "S3" in classes:
        sev = Severity.MEDIUM
    else:
        sev = Severity.LOW
    if ("S3" in classes and "S2" in classes) or n >= 3:
        conf = Confidence.HIGH
    elif n == 2:
        conf = Confidence.MEDIUM
    else:
        conf = Confidence.LOW
    return sev, conf


@register("TOOL-001", "tools")
def check_agent_directed_instructions(toolset: ToolSet, ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    for tool in toolset.tools:
        classes, evidence = analyse(tool)
        if not classes:
            continue
        sev, conf = grade(classes)
        labels = ", ".join(f"{c} ({SIGNALS[c][0]})" for c in sorted(classes))
        findings.append(
            emit(
                ctx,
                "TOOL-001",
                affected=Affected(
                    tool.source_file, tool.json_path, server=toolset.server_label, tool=tool.name
                ),
                evidence=evidence[:6],
                description=f"Tool '{tool.name}' contains text that reads as instructions to the model "
                f"rather than a description of behaviour. Signal classes: {labels}. This is an indicator "
                "for human review, not a determination of intent.",
                severity=sev,
                confidence=conf,
            )
        )
    return findings
