"""Orchestration: discovery -> loaders -> package code -> checks -> Report. Pure Python, no CLI."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp_trustcheck import __version__, checks
from mcp_trustcheck.checks.config.secrets import collect_sensitive_values
from mcp_trustcheck.code.extract import analyse_servers
from mcp_trustcheck.discovery import (
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_FILES,
    LoadedFile,
    discover,
    load_one,
)
from mcp_trustcheck.loaders.config import load_servers
from mcp_trustcheck.loaders.tools import load_toolset
from mcp_trustcheck.lock import LockError, baselines_from_lock, build_lock, load_lock
from mcp_trustcheck.model import Confidence, Report, ScannedFile, Severity, SkippedFile, ToolSet

__all__ = [
    "DEFAULT_MAX_BYTES",
    "DEFAULT_MAX_FILES",
    "LOCK_RULES",
    "ScanError",
    "ScanOptions",
    "diff",
    "load_baseline",
    "lock",
    "scan",
    "verify",
    "worst_severity",
]

# Rules that only fire against a baseline or lock; `scan examples/` cannot trigger them.
LOCK_RULES = frozenset({"TOOL-006", "CFG-020"})


@dataclass
class ScanOptions:
    inputs: list[str]
    baseline: str | None = None
    rules: set[str] | None = None
    exclude_rules: set[str] = field(default_factory=set)
    min_confidence: Confidence = Confidence.LOW
    follow_symlinks: bool = False
    max_bytes: int = DEFAULT_MAX_BYTES
    max_files: int = DEFAULT_MAX_FILES
    packages: bool = True  # read the launched packages' code from local caches (docs/design.md §8)
    package_paths: dict[str, str] = field(default_factory=dict)  # server name -> code path
    lock: str | None = None


class ScanError(Exception):
    """A usage-level problem (bad baseline, nothing to scan)."""


def load_baseline(path: str, *, max_bytes: int = DEFAULT_MAX_BYTES) -> ToolSet:
    p = Path(path)
    try:
        root = p.resolve(strict=True)
    except OSError as exc:
        raise ScanError(f"baseline not found: {path}") from exc
    res = load_one(root, [root], max_bytes=max_bytes, follow_symlinks=True)
    if isinstance(res, SkippedFile):
        raise ScanError(f"baseline {path} unusable: {res.reason} {res.detail or ''}".strip())
    if res.kind != "tools":
        raise ScanError(f"baseline {path} is not a tool catalogue (detected: {res.kind})")
    return load_toolset(res.data, res.dialect, res.display)


def _selected_rules(opts: ScanOptions) -> list[str]:
    available = set(checks.registered_rule_ids())
    chosen = set(opts.rules) if opts.rules else available
    unknown = (chosen | opts.exclude_rules) - available
    if unknown:
        raise ScanError("unknown rule id(s): " + ", ".join(sorted(unknown)))
    return sorted(chosen - opts.exclude_rules)


def _run(opts: ScanOptions) -> tuple[Report, checks.Context]:
    if not opts.inputs:
        raise ScanError("no inputs given")
    rules = _selected_rules(opts)
    disc = discover(
        opts.inputs,
        max_bytes=opts.max_bytes,
        follow_symlinks=opts.follow_symlinks,
        max_files=opts.max_files,
    )

    ctx = checks.Context()
    scanned: list[ScannedFile] = []
    for lf in disc.loaded:
        _ingest(lf, ctx, scanned)
    if opts.baseline:
        ctx.baseline = load_baseline(opts.baseline, max_bytes=opts.max_bytes)
        ctx.baseline_path = opts.baseline
    if opts.lock:
        try:
            ctx.lock = load_lock(opts.lock)
        except LockError as exc:
            raise ScanError(str(exc)) from exc
        ctx.lock_path = opts.lock
        ctx.baselines = baselines_from_lock(ctx.lock, opts.lock)
    if not scanned:
        reasons = (
            ", ".join(
                f"{s.path} ({s.reason}{': ' + s.detail if s.detail else ''})"
                for s in disc.skipped[:5]
            )
            or "no JSON files found"
        )
        raise ScanError(f"nothing to scan: {reasons}")

    if opts.packages:
        overrides = {name: Path(p).expanduser() for name, p in opts.package_paths.items()}
        unknown = set(overrides) - {s.name for s in ctx.servers}
        if unknown:
            raise ScanError("--package-path names no scanned server: " + ", ".join(sorted(unknown)))
        manifests, missing = analyse_servers(ctx.servers, ctx.config_dirs, overrides=overrides)
        ctx.manifests = {m.server: m for m in manifests}
        ctx.unlocated = missing

    collect_sensitive_values(ctx.servers, ctx.redactor)
    for m in ctx.manifests.values():
        m.redact(ctx.redactor)
    findings = [
        f for f in checks.run_checks(ctx, rules) if f.confidence.rank >= opts.min_confidence.rank
    ]
    report = Report(
        tool_version=__version__,
        generated_at=datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        inputs=list(opts.inputs),
        files_scanned=scanned,
        files_skipped=disc.skipped,
        rules_run=rules,
        findings=findings,
        baseline=opts.baseline,
        errors=[e.to_dict() for e in ctx.errors],
        lock=opts.lock,
        packages=list(ctx.manifests.values()),
        unlocated=list(ctx.unlocated),
    )
    return report, ctx


def scan(opts: ScanOptions) -> Report:
    return _run(opts)[0]


def _ingest(lf: LoadedFile, ctx: checks.Context, scanned: list[ScannedFile]) -> None:
    if lf.kind == "config":
        servers = load_servers(lf.data, lf.dialect, lf.display)
        ctx.servers.extend(servers)
        ctx.config_dirs[lf.display] = lf.path.resolve().parent
        scanned.append(ScannedFile(lf.display, "config", lf.dialect, servers=len(servers)))
    else:
        ts = load_toolset(lf.data, lf.dialect, lf.display)
        ctx.toolsets.append(ts)
        scanned.append(ScannedFile(lf.display, "tools", lf.dialect, tools=len(ts.tools)))


def diff(baseline: str, current: str, *, max_bytes: int = DEFAULT_MAX_BYTES) -> Report:
    return scan(
        ScanOptions(
            inputs=[current],
            baseline=baseline,
            rules={"TOOL-006"},
            max_bytes=max_bytes,
            packages=False,
        )
    )


def lock(opts: ScanOptions) -> tuple[Report, dict[str, Any]]:
    """Scan, then record the reviewed state of every server as a lock document."""
    report, ctx = _run(opts)
    return report, build_lock(ctx.servers, ctx.manifests, ctx.toolsets)


def verify(opts: ScanOptions) -> Report:
    """Drift rules only (CFG-020 and TOOL-006) against the lock named in `opts.lock`."""
    if not opts.lock:
        raise ScanError("verify needs --lock FILE")
    opts.rules = set(LOCK_RULES)
    opts.exclude_rules = set()
    return scan(opts)


def worst_severity(report: Report) -> Severity | None:
    if not report.findings:
        return None
    return max((f.severity for f in report.findings), key=lambda s: s.rank)
