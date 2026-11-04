"""Check protocol, registry and the single Finding constructor.

A check is a pure function `(ServerConfig | ToolSet, Context) -> list[Finding]`. No I/O.
Every Finding is built through `emit`, which pulls rule metadata from `rules_catalog` and
passes each evidence snippet through the scan's `Redactor` before it is stored.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from mcp_trustcheck import rules_catalog
from mcp_trustcheck.model import (
    Affected,
    Confidence,
    Evidence,
    Finding,
    Kind,
    ServerConfig,
    Severity,
    ToolSet,
    finding_id,
)
from mcp_trustcheck.redaction import Redactor


@dataclass
class Context:
    redactor: Redactor = field(default_factory=Redactor)
    servers: list[ServerConfig] = field(default_factory=list)
    toolsets: list[ToolSet] = field(default_factory=list)
    baseline: ToolSet | None = None
    baseline_path: str | None = None
    state: dict[str, Any] = field(default_factory=dict)  # scratch space for cross-item checks
    errors: list[CheckError] = field(default_factory=list)


ConfigCheck = Callable[[ServerConfig, Context], list[Finding]]
ToolSetCheck = Callable[[ToolSet, Context], list[Finding]]


@dataclass(frozen=True)
class Check:
    rule_id: str
    scope: str  # "config" | "tools"
    fn: ConfigCheck | ToolSetCheck


_REGISTRY: dict[str, Check] = {}


def register(
    rule_id: str, scope: str
) -> Callable[[ConfigCheck | ToolSetCheck], ConfigCheck | ToolSetCheck]:
    if rule_id not in rules_catalog.RULES:
        raise KeyError(f"{rule_id} is not described in rules_catalog")

    def deco(fn: ConfigCheck | ToolSetCheck) -> ConfigCheck | ToolSetCheck:
        _REGISTRY[rule_id] = Check(rule_id, scope, fn)
        return fn

    return deco


def registered_rule_ids() -> list[str]:
    return sorted(_REGISTRY)


def emit(
    ctx: Context,
    rule_id: str,
    *,
    affected: Affected,
    evidence: Iterable[tuple[str, str] | tuple[str, str, str | None]],
    description: str,
    severity: Severity | None = None,
    confidence: Confidence | None = None,
    kind: Kind | None = None,
    key: str = "",
) -> Finding:
    meta = rules_catalog.get(rule_id)
    ev: list[Evidence] = []
    for item in evidence:
        path, snippet = item[0], item[1]
        note = item[2] if len(item) > 2 else None
        ev.append(Evidence(json_path=path, snippet=ctx.redactor.snippet(snippet), note=note))
    if not ev:
        ev.append(Evidence(json_path=affected.json_path, snippet="(no snippet)"))
    return Finding(
        id=finding_id(rule_id, affected.file, affected.json_path, key),
        rule_id=rule_id,
        title=meta.title,
        description=ctx.redactor.scrub(description),
        kind=kind or meta.kind,
        severity=severity or meta.severity,
        confidence=confidence or meta.confidence,
        affected=affected,
        evidence=ev,
        impact=meta.impact,
        mitigation=meta.mitigation,
        references=list(meta.references),
        limitations=meta.limitations,
        spec_note=meta.spec_note,
        standards=list(meta.standards),
    )


@dataclass(frozen=True)
class CheckError:
    rule_id: str
    file: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"rule_id": self.rule_id, "file": self.file, "message": self.message}


def run_checks(ctx: Context, rule_ids: Iterable[str] | None = None) -> list[Finding]:
    """Run the selected rules. A rule that raises on one item is recorded in `ctx.errors` and the
    scan continues: one defective rule must never hide the findings of the others."""
    selected = set(rule_ids) if rule_ids is not None else set(_REGISTRY)
    findings: list[Finding] = []
    for rid in sorted(selected):
        check = _REGISTRY.get(rid)
        if check is None:
            continue
        items: list[Any] = list(ctx.servers) if check.scope == "config" else list(ctx.toolsets)
        for item in items:
            try:
                findings.extend(check.fn(item, ctx))
            except Exception as exc:
                ctx.errors.append(
                    CheckError(rid, item.source_file, f"{type(exc).__name__}: {exc}"[:300])
                )
    return findings


# Import rule modules so they register themselves. Keep at the bottom to avoid cycles.
from mcp_trustcheck.checks.config import (  # noqa: E402
    approval,
    container,
    dangerous,
    duplicates,
    env,
    execution,
    filesystem,
    packages,
    secrets,
    transport,
)
from mcp_trustcheck.checks.tools import (  # noqa: E402
    annotation_hints,
    collisions,
    drift,
    headers,
    hidden,
    ingress,
    instructions,
    schema,
)

__all__ = [
    "Check",
    "CheckError",
    "Context",
    "annotation_hints",
    "approval",
    "collisions",
    "container",
    "dangerous",
    "drift",
    "duplicates",
    "emit",
    "env",
    "execution",
    "filesystem",
    "headers",
    "hidden",
    "ingress",
    "instructions",
    "packages",
    "register",
    "registered_rule_ids",
    "run_checks",
    "schema",
    "secrets",
    "transport",
]
