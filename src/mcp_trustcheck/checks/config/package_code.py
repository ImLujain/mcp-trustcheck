"""CFG-018 install hooks; CFG-019 runtime code loading; CFG-020 drift against a lock.

All three read `ctx.manifests`, produced from code already on disk (docs/design.md §8). A server
whose package could not be located yields nothing here; the report's `packages` section says why.
"""

from __future__ import annotations

from typing import Any

from mcp_trustcheck.checks import Context, emit, register
from mcp_trustcheck.code.model import PHRASES, WEAK_DYNAMIC_CALLEES, PackageManifest, Sink
from mcp_trustcheck.model import Affected, Confidence, Finding, Kind, ServerConfig, Severity


def _sink_evidence(
    path: str, sinks: list[Sink], limit: int = 3
) -> list[tuple[str, str, str | None]]:
    out: list[tuple[str, str, str | None]] = []
    for s in sinks[:limit]:
        out.append(
            (path, f"{s.file}:{s.line} {s.snippet or s.callee}", f"{PHRASES[s.cls]} via {s.callee}")
        )
    return out


@register("CFG-018", "config")
def check_install_hooks(server: ServerConfig, ctx: Context) -> list[Finding]:
    m = ctx.manifests.get(server.name)
    if m is None or not m.install_hooks:
        return []
    path = f"{server.json_path}.command"
    evidence = [
        (path, f"{k}: {v}", "runs at install time, before any approval")
        for k, v in sorted(m.install_hooks.items())
    ]
    names = ", ".join(sorted(m.install_hooks))
    return [
        emit(
            ctx,
            "CFG-018",
            affected=Affected(server.source_file, path, server=server.name),
            evidence=evidence,
            description=f"Server '{server.name}' launches {m.name}"
            + (f"@{m.version}" if m.version else "")
            + f" ({m.root}), which declares install-time script(s): {names}. These run when the launcher "
            "installs or updates the package, not when a tool is called.",
        )
    ]


@register("CFG-019", "config")
def check_runtime_code_loading(server: ServerConfig, ctx: Context) -> list[Finding]:
    m = ctx.manifests.get(server.name)
    if m is None:
        return []
    strong = [
        s for s in m.sinks if s.cls == "dynamic_code" and s.callee not in WEAK_DYNAMIC_CALLEES
    ]
    if not strong:
        return []
    net = [s for s in m.sinks if s.cls == "network"]
    path = f"{server.json_path}.command"
    if net:
        sev, conf = Severity.MEDIUM, Confidence.MEDIUM
        what = "both reaches the network and evaluates code at runtime"
    else:
        sev, conf = Severity.LOW, Confidence.MEDIUM
        what = "evaluates code at runtime"
    hosts = ", ".join(m.hosts[:3]) if m.hosts else None
    return [
        emit(
            ctx,
            "CFG-019",
            affected=Affected(server.source_file, path, server=server.name),
            evidence=_sink_evidence(path, strong) + _sink_evidence(path, net, 1),
            description=f"Server '{server.name}' launches {m.name} ({m.root}), whose code {what}"
            + (f" (hosts seen: {hosts})" if hosts else "")
            + ". Behaviour can change after review without any change on disk.",
            severity=sev,
            confidence=conf,
        )
    ]


def _lock_entry(ctx: Context, server: ServerConfig) -> dict[str, Any] | None:
    if not ctx.lock:
        return None
    servers = ctx.lock.get("servers")
    if not isinstance(servers, dict):
        return None
    entry = servers.get(server.name)
    return entry if isinstance(entry, dict) else None


def _tool_classes(entry: dict[str, Any]) -> dict[str, set[str]]:
    caps = entry.get("capabilities") or {}
    tools = caps.get("tools") if isinstance(caps, dict) else None
    out: dict[str, set[str]] = {}
    if isinstance(tools, dict):
        for name, classes in tools.items():
            if isinstance(classes, list):
                out[str(name)] = {str(c) for c in classes}
    return out


def _package_classes(entry: dict[str, Any]) -> set[str]:
    caps = entry.get("capabilities") or {}
    pk = caps.get("package") if isinstance(caps, dict) else None
    return {str(c) for c in pk} if isinstance(pk, list) else set()


@register("CFG-020", "config")
def check_lock_drift(server: ServerConfig, ctx: Context) -> list[Finding]:
    if not ctx.lock:
        return []
    path = f"{server.json_path}.command"
    affected = Affected(server.source_file, path, server=server.name)
    lock_note = f"lock: {ctx.lock_path}" if ctx.lock_path else "lock"
    entry = _lock_entry(ctx, server)
    if entry is None:
        return [
            emit(
                ctx,
                "CFG-020",
                affected=affected,
                evidence=[(server.json_path, server.name, f"not present in {lock_note}")],
                description=f"Server '{server.name}' is not in the lock; it was added since the last review.",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                key="unlocked",
            )
        ]
    findings: list[Finding] = []
    launch = entry.get("launch")
    if isinstance(launch, str) and launch != server.command_line:
        findings.append(
            emit(
                ctx,
                "CFG-020",
                affected=affected,
                evidence=[(path, server.command_line, f"locked: {launch}")],
                description=f"Server '{server.name}' launch line differs from the lock.",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                key="launch",
            )
        )
    locked_pkg = entry.get("package") if isinstance(entry.get("package"), dict) else None
    m: PackageManifest | None = ctx.manifests.get(server.name)
    if locked_pkg and m is None:
        findings.append(
            emit(
                ctx,
                "CFG-020",
                affected=affected,
                evidence=[
                    (
                        path,
                        str(locked_pkg.get("name")),
                        f"locked {locked_pkg.get('version') or 'unversioned'}; not located now",
                    )
                ],
                description=f"Server '{server.name}': the locked package can no longer be located locally, so its "
                "code could not be compared.",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                kind=Kind.INFO,
                key="missing",
            )
        )
        return findings
    if m is None:
        return findings
    if locked_pkg:
        lv, ld = locked_pkg.get("version"), locked_pkg.get("digest")
        if lv and m.version and lv != m.version:
            findings.append(
                emit(
                    ctx,
                    "CFG-020",
                    affected=affected,
                    evidence=[(path, f"{m.name}@{m.version}", f"locked {m.name}@{lv}")],
                    description=f"Server '{server.name}': package version changed from {lv} to {m.version} since the lock.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    key="version",
                )
            )
        elif ld and ld != m.digest:
            findings.append(
                emit(
                    ctx,
                    "CFG-020",
                    affected=affected,
                    evidence=[
                        (
                            path,
                            f"sha256 {str(ld)[:12]} → {m.digest[:12]}",
                            "same version, different files",
                        )
                    ],
                    description=f"Server '{server.name}': the package's files changed although the version "
                    f"({m.version or 'unversioned'}) did not. That is the shape of a tampered or re-published package.",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    key="digest",
                )
            )
    new_pkg = m.classes - _package_classes(entry)
    if new_pkg:
        sinks = [s for s in m.sinks if s.cls in new_pkg]
        findings.append(
            emit(
                ctx,
                "CFG-020",
                affected=affected,
                evidence=_sink_evidence(path, sinks),
                description=f"Server '{server.name}': the package can now {', '.join(PHRASES[c] for c in sorted(new_pkg))}, "
                "which it could not when the lock was written.",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                key="caps",
            )
        )
    locked_tools = _tool_classes(entry)
    for name, tc in sorted(m.tools.items()):
        if name not in locked_tools:
            if tc.handler:
                findings.append(
                    emit(
                        ctx,
                        "CFG-020",
                        affected=Affected(server.source_file, path, server=server.name, tool=name),
                        evidence=[(path, name, f"handler at {tc.handler}; not in {lock_note}")],
                        description=f"Server '{server.name}': tool '{name}' is implemented in the code but was not in the lock.",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        key=f"newtool:{name}",
                    )
                )
            continue
        gained = tc.classes - locked_tools[name]
        if gained:
            findings.append(
                emit(
                    ctx,
                    "CFG-020",
                    affected=Affected(server.source_file, path, server=server.name, tool=name),
                    evidence=_sink_evidence(path, [s for s in tc.sinks if s.cls in gained]),
                    description=f"Server '{server.name}': tool '{name}' can now {', '.join(PHRASES[c] for c in sorted(gained))}; "
                    "it could not when the lock was written.",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    key=f"tool:{name}",
                )
            )
    raw_hooks = entry.get("install_hooks")
    locked_hooks: dict[str, Any] = raw_hooks if isinstance(raw_hooks, dict) else {}
    new_hooks = {k: v for k, v in m.install_hooks.items() if k not in locked_hooks}
    if new_hooks:
        findings.append(
            emit(
                ctx,
                "CFG-020",
                affected=affected,
                evidence=[
                    (path, f"{k}: {v}", "install hook not in lock")
                    for k, v in sorted(new_hooks.items())
                ],
                description=f"Server '{server.name}': the package gained install-time script(s) {', '.join(sorted(new_hooks))}.",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                key="hooks",
            )
        )
    return findings
