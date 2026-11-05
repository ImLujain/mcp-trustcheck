"""Core data model (docs/design.md §3).

Everything here is plain data. Checks produce `Finding`s; reporters consume a `Report`.
No I/O lives in this module.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from mcp_trustcheck.code.model import PackageManifest, UnlocatedPackage


class Severity(str, Enum):
    """Impact *if the finding is true* (threat-model.md §5). Not a score."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class Confidence(str, Enum):
    """How deterministic the detection is (threat-model.md §5)."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return _CONFIDENCE_RANK[self]


_CONFIDENCE_RANK = {Confidence.HIGH: 2, Confidence.MEDIUM: 1, Confidence.LOW: 0}


class Kind(str, Enum):
    WEAKNESS = "weakness"  # a documented security property is not met
    INDICATOR = "indicator"  # needs human review; not asserted as a flaw
    INFO = "info"  # surface enumeration; no weakness asserted


# --------------------------------------------------------------------------- inputs


@dataclass(frozen=True)
class ConfigValue:
    """A string from a config file plus whether it is a literal or a `${...}` reference."""

    value: str
    literal: bool
    json_path: str


@dataclass
class ServerConfig:
    name: str
    source_file: str
    json_path: str
    dialect: str
    transport: str  # "stdio" | "http" | "sse" | "unknown"
    command: str | None = None
    args: list[ConfigValue] = field(default_factory=list)
    env: dict[str, ConfigValue] = field(default_factory=dict)
    url: ConfigValue | None = None
    headers: dict[str, ConfigValue] = field(default_factory=dict)
    auto_approve: list[str] = field(default_factory=list)
    auto_approve_all: bool = False
    trust: bool | None = None
    disabled: bool = False
    unparsed_keys: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def arg_values(self) -> list[str]:
        return [a.value for a in self.args]

    @property
    def command_line(self) -> str:
        parts = ([self.command] if self.command else []) + self.arg_values
        return " ".join(parts)


@dataclass
class ToolDefinition:
    name: str
    source_file: str
    json_path: str
    server_label: str
    title: str | None = None
    description: str | None = None
    input_schema: dict[str, Any] | None = None
    output_schema: dict[str, Any] | None = None
    annotations: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolSet:
    source_file: str
    server_label: str
    shape: str  # "jsonrpc-result" | "tools-object" | "array"
    tools: list[ToolDefinition] = field(default_factory=list)


# --------------------------------------------------------------------------- findings


@dataclass(frozen=True)
class Reference:
    title: str
    url: str

    def to_dict(self) -> dict[str, str]:
        return {"title": self.title, "url": self.url}


@dataclass(frozen=True)
class Standard:
    """A weakness-taxonomy or risk-catalogue entry the rule maps to (CWE, OWASP MCP Top 10, ...).

    Distinct from `Reference`: a reference is reading material; a standard is a stable identifier a
    reviewer can cite in a report or map to a control framework.
    """

    framework: str  # "CWE" | "OWASP MCP Top 10" | "OWASP LLM Top 10"
    id: str  # "CWE-798", "MCP01:2025", "LLM02:2025"
    title: str
    url: str

    @property
    def label(self) -> str:
        return f"{self.id} {self.title}"

    def to_dict(self) -> dict[str, str]:
        return {"framework": self.framework, "id": self.id, "title": self.title, "url": self.url}


@dataclass(frozen=True)
class Evidence:
    json_path: str
    snippet: str  # always redacted and <= 512 chars by the time it is stored
    note: str | None = None

    def to_dict(self) -> dict[str, str]:
        d = {"json_path": self.json_path, "snippet": self.snippet}
        if self.note:
            d["note"] = self.note
        return d


@dataclass(frozen=True)
class Affected:
    file: str
    json_path: str
    server: str | None = None
    tool: str | None = None

    def to_dict(self) -> dict[str, str]:
        d = {"file": self.file, "json_path": self.json_path}
        if self.server is not None:
            d["server"] = self.server
        if self.tool is not None:
            d["tool"] = self.tool
        return d


def finding_id(rule_id: str, file: str, json_path: str, key: str = "") -> str:
    digest = hashlib.sha256(f"{rule_id}\x00{file}\x00{json_path}\x00{key}".encode()).hexdigest()
    return f"{rule_id}-{digest[:8]}"


@dataclass
class Finding:
    id: str
    rule_id: str
    title: str
    description: str
    kind: Kind
    severity: Severity
    confidence: Confidence
    affected: Affected
    evidence: list[Evidence]
    impact: str
    mitigation: str
    references: list[Reference]
    limitations: str
    spec_note: str | None = None
    standards: list[Standard] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "kind": self.kind.value,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "affected": self.affected.to_dict(),
            "evidence": [e.to_dict() for e in self.evidence],
            "impact": self.impact,
            "mitigation": self.mitigation,
            "references": [r.to_dict() for r in self.references],
            "standards": [s.to_dict() for s in self.standards],
            "limitations": self.limitations,
        }
        if self.spec_note:
            d["spec_note"] = self.spec_note
        return d


# --------------------------------------------------------------------------- report


@dataclass
class ScannedFile:
    path: str
    kind: str  # "config" | "tools"
    dialect: str
    servers: int = 0
    tools: int = 0

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"path": self.path, "kind": self.kind, "dialect": self.dialect}
        if self.kind == "config":
            d["servers"] = self.servers
        else:
            d["tools"] = self.tools
        return d


@dataclass
class SkippedFile:
    path: str
    reason: str
    detail: str | None = None

    def to_dict(self) -> dict[str, str]:
        d = {"path": self.path, "reason": self.reason}
        if self.detail:
            d["detail"] = self.detail
        return d


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (
            -f.severity.rank,
            -f.confidence.rank,
            f.affected.file,
            f.affected.json_path,
            f.rule_id,
        ),
    )


@dataclass
class Report:
    tool_version: str
    generated_at: str
    inputs: list[str]
    files_scanned: list[ScannedFile]
    files_skipped: list[SkippedFile]
    rules_run: list[str]
    findings: list[Finding]
    baseline: str | None = None
    errors: list[dict[str, str]] = field(default_factory=list)
    schema_version: str = "1.2"
    lock: str | None = None
    packages: list[PackageManifest] = field(default_factory=list)
    unlocated: list[UnlocatedPackage] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        findings = sort_findings(self.findings)
        by_sev = {s.value: 0 for s in Severity}
        by_conf = {c.value: 0 for c in Confidence}
        by_kind = {k.value: 0 for k in Kind}
        by_std: dict[str, int] = {}
        for f in findings:
            by_sev[f.severity.value] += 1
            by_conf[f.confidence.value] += 1
            by_kind[f.kind.value] += 1
            for std in f.standards:
                by_std[std.id] = by_std.get(std.id, 0) + 1
        return {
            "schema_version": self.schema_version,
            "tool": {"name": "mcp-trustcheck", "version": self.tool_version},
            "generated_at": self.generated_at,
            "scan": {
                "inputs": list(self.inputs),
                "files_scanned": [f.to_dict() for f in self.files_scanned],
                "files_skipped": [f.to_dict() for f in self.files_skipped],
                "rules_run": sorted(self.rules_run),
                "baseline": self.baseline,
                "lock": self.lock,
                "errors": list(self.errors),
            },
            "summary": {
                "total": len(findings),
                "by_severity": by_sev,
                "by_confidence": by_conf,
                "by_kind": by_kind,
                "by_standard": dict(sorted(by_std.items())),
            },
            "packages": [p.to_dict() for p in self.packages]
            + [u.to_dict() for u in self.unlocated],
            "findings": [f.to_dict() for f in findings],
        }
