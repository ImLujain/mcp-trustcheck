"""TOOL-005: underspecified tool definition (threat-model.md T1/T7)."""

from __future__ import annotations

import re
from typing import Any

from mcp_trustcheck.checks import Context, emit, register
from mcp_trustcheck.loaders.config import jkey
from mcp_trustcheck.model import Affected, Confidence, Finding, Severity, ToolSet

FREEFORM_RE = re.compile(
    r"(?i)^(?:command|cmd|shell|script|sql|query|path|file_?path|url|uri|code|expression|expr|args?|arguments|raw|payload|template|regex|pattern|filter)$"
)
CONSTRAINT_KEYS = {"enum", "const", "pattern", "maxLength", "format"}
MIN_DESC = 10


@register("TOOL-005", "tools")
def check_underspecified(toolset: ToolSet, ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    for tool in toolset.tools:
        issues: list[tuple[str, str, str | None]] = []
        worst = Severity.LOW
        if not tool.description or len(tool.description.strip()) < MIN_DESC:
            issues.append(
                (
                    f"{tool.json_path}.description",
                    repr(tool.description or ""),
                    "missing or trivial description",
                )
            )
        schema = tool.input_schema
        if schema is None:
            issues.append(
                (
                    f"{tool.json_path}.inputSchema",
                    "(absent)",
                    "inputSchema missing; spec requires a JSON Schema object",
                )
            )
        else:
            props = schema.get("properties")
            if not isinstance(props, dict) or not props:
                if schema.get("additionalProperties") is not False:
                    issues.append(
                        (
                            f"{tool.json_path}.inputSchema",
                            _short(schema),
                            "accepts any object; no declared parameters",
                        )
                    )
            else:
                for pname, pschema in props.items():
                    if not isinstance(pschema, dict):
                        continue
                    ppath = f"{tool.json_path}.inputSchema.properties{jkey(str(pname))}"
                    if (
                        FREEFORM_RE.match(str(pname))
                        and pschema.get("type") in ("string", None)
                        and not (CONSTRAINT_KEYS & set(pschema))
                    ):
                        issues.append(
                            (
                                ppath,
                                _short(pschema),
                                f"free-form `{pname}` string with no enum/pattern/maxLength",
                            )
                        )
                        worst = Severity.MEDIUM
        if not issues:
            continue
        findings.append(
            emit(
                ctx,
                "TOOL-005",
                affected=Affected(
                    tool.source_file, tool.json_path, server=toolset.server_label, tool=tool.name
                ),
                evidence=issues[:6],
                description=f"Tool '{tool.name}' is underspecified: "
                + "; ".join(i[2] or "" for i in issues[:4])
                + ".",
                severity=worst,
                confidence=Confidence.HIGH,
            )
        )
    return findings


def _short(obj: Any) -> str:
    import json

    s = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    return s if len(s) <= 160 else s[:159] + "…"
