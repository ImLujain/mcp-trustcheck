"""Intermediate results shared by the language analysers and the extraction driver."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from mcp_trustcheck.code.model import SNIPPET_MAX, Sink
from mcp_trustcheck.redaction import match_known_pattern, redact

_URL_RE = re.compile(
    r"\b(?:https?|wss?|ftp|smtp|ssh|redis|postgres(?:ql)?|mongodb(?:\+srv)?|mysql)://([^/\s\"'`:?#]+)"
)


@dataclass
class FunctionInfo:
    key: str  # unique: "<file>::<qualified name>"
    name: str  # bare name used for call resolution
    file: str
    line: int
    sinks: list[Sink] = field(default_factory=list)
    calls: set[str] = field(default_factory=set)  # "name" or "module_hint|name"


@dataclass
class ModuleResult:
    file: str
    functions: dict[str, FunctionInfo] = field(default_factory=dict)
    sinks: list[Sink] = field(default_factory=list)
    tools: dict[str, str] = field(default_factory=dict)  # tool name -> function key or bare name
    weak_tools: set[str] = field(default_factory=set)  # names found via a loosely-typed dispatcher
    declared: set[str] = field(default_factory=set)
    notes: list[str] = field(default_factory=list)
    attribution: str = "none"  # "ast" | "lexical" | "none"
    module_name: str = ""  # last path segment without suffix, for `module.func` resolution


def safe_snippet(line: str) -> str:
    """A source line, trimmed, with any recognisable secret literal redacted."""
    text = " ".join(line.split())
    pat = match_known_pattern(text)
    if pat is not None:
        text = pat.regex.sub(lambda m: redact(m.group(0)), text)
    if len(text) > SNIPPET_MAX:
        text = text[: SNIPPET_MAX - 1] + "…"
    return text


def host_of_literal(text: str) -> str | None:
    """The host of the first URL-like literal in `text`, if any."""
    m = _URL_RE.search(text)
    if not m:
        return None
    return m.group(1).strip("[]").lower()


def hosts_in(text: str) -> list[str]:
    return sorted({m.group(1).strip("[]").lower() for m in _URL_RE.finditer(text)})
