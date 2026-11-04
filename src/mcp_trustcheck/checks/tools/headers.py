"""CFG-015 sensitive parameter in x-mcp-header; TOOL-009 invalid x-mcp-header (MCP 2026-07-28)."""

from __future__ import annotations

import re
from typing import Any

from mcp_trustcheck.checks import Context, emit, register
from mcp_trustcheck.loaders.config import jkey
from mcp_trustcheck.model import Affected, Finding, ToolDefinition, ToolSet
from mcp_trustcheck.redaction import looks_like_secret_key

_TCHAR_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_PII_RE = re.compile(
    r"(?i)\b(?:ssn|social[-_ ]?security|passport|email|e-mail|phone|address|dob|birth|credit[-_ ]?card|card[-_ ]?number|iban|account[-_ ]?number|pii|personal)\b"
)
_PRIMITIVE = {"string", "integer", "boolean"}


def walk_headers(schema: dict[str, Any], base: str) -> list[tuple[str, str, dict[str, Any], bool]]:
    """Return (json_path, property_name, property_schema, statically_reachable) for every x-mcp-header."""
    out: list[tuple[str, str, dict[str, Any], bool]] = []

    def visit(node: Any, path: str, reachable: bool, name: str) -> None:
        if isinstance(node, dict):
            if "x-mcp-header" in node:
                out.append((path, name, node, reachable))
            for k, v in node.items():
                if k == "properties" and isinstance(v, dict):
                    for pn, ps in v.items():
                        visit(ps, f"{path}.properties{jkey(str(pn))}", reachable, str(pn))
                elif isinstance(v, (dict, list)):
                    # Not reached through a `properties` key => not statically reachable.
                    visit(v, f"{path}{jkey(str(k))}", False, name)
        elif isinstance(node, list):
            for i, item in enumerate(node):
                visit(item, f"{path}[{i}]", False, name)

    visit(schema, base, True, "")
    return out


def _headers_of(tool: ToolDefinition) -> list[tuple[str, str, dict[str, Any], bool]]:
    if not tool.input_schema:
        return []
    return walk_headers(tool.input_schema, f"{tool.json_path}.inputSchema")


@register("TOOL-009", "tools")
def check_invalid_headers(toolset: ToolSet, ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    for tool in toolset.tools:
        entries = _headers_of(tool)
        if not entries:
            continue
        problems: list[tuple[str, str, str | None]] = []
        seen: dict[str, str] = {}
        for path, _pname, pschema, reachable in entries:
            hv = pschema.get("x-mcp-header")
            hpath = f"{path}" + '["x-mcp-header"]'
            if not isinstance(hv, str) or not hv:
                problems.append((hpath, repr(hv), "empty or non-string header name"))
                continue
            if not _TCHAR_RE.match(hv) or re.search(r"[\r\n\x00-\x1f]", hv):
                problems.append((hpath, hv, "not a valid HTTP field-name token (RFC 9110 tchar)"))
            low = hv.lower()
            if low in seen:
                problems.append((hpath, hv, f"duplicates header '{seen[low]}' (case-insensitive)"))
            seen[low] = hv
            ptype = pschema.get("type")
            if ptype == "number":
                problems.append(
                    (hpath, hv, "type `number` is not permitted; only string/integer/boolean")
                )
            elif ptype not in _PRIMITIVE:
                problems.append((hpath, hv, f"type {ptype!r} is not a permitted primitive"))
            if not reachable:
                problems.append(
                    (
                        hpath,
                        hv,
                        "not statically reachable (under items/oneOf/anyOf/allOf/not/if/$ref)",
                    )
                )
        if problems:
            findings.append(
                emit(
                    ctx,
                    "TOOL-009",
                    affected=Affected(
                        tool.source_file,
                        f"{tool.json_path}.inputSchema",
                        server=toolset.server_label,
                        tool=tool.name,
                    ),
                    evidence=problems[:6],
                    description=f"Tool '{tool.name}' has {len(problems)} invalid x-mcp-header declaration(s); conforming "
                    "clients must exclude the tool from tools/list.",
                )
            )
    return findings


@register("CFG-015", "tools")
def check_sensitive_header_param(toolset: ToolSet, ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    for tool in toolset.tools:
        for path, pname, pschema, _reachable in _headers_of(tool):
            desc = str(pschema.get("description", ""))
            why = None
            if looks_like_secret_key(pname) or looks_like_secret_key(desc):
                why = "credential vocabulary"
            elif _PII_RE.search(pname) or _PII_RE.search(desc):
                why = "personal-data vocabulary"
            if why is None:
                continue
            findings.append(
                emit(
                    ctx,
                    "CFG-015",
                    affected=Affected(
                        tool.source_file, path, server=toolset.server_label, tool=tool.name
                    ),
                    evidence=[
                        (
                            path + '["x-mcp-header"]',
                            str(pschema.get("x-mcp-header")),
                            f"parameter `{pname}` matches {why}",
                        )
                    ],
                    description=f"Tool '{tool.name}' mirrors parameter `{pname}` into an HTTP header ({why}); header values "
                    "are visible to every network intermediary.",
                    key=pname,
                )
            )
    return findings
