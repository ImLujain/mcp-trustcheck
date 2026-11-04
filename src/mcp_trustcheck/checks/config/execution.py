"""CFG-003: shell-mediated server execution (threat-model.md T6)."""

from __future__ import annotations

from mcp_trustcheck.checks import Context, emit, register
from mcp_trustcheck.checks._util import (
    ENCODED_FLAGS,
    SHELL_CMD_FLAGS,
    basename,
    find_metachars,
    is_shell,
)
from mcp_trustcheck.model import Affected, Confidence, Finding, Kind, ServerConfig, Severity


@register("CFG-003", "config")
def check_shell_execution(server: ServerConfig, ctx: Context) -> list[Finding]:
    if not server.command:
        return []
    affected = Affected(server.source_file, server.json_path, server=server.name)
    args = server.arg_values
    cmdline = server.command_line

    if is_shell(server.command):
        shell = basename(server.command)
        flag_idx = next((i for i, a in enumerate(args) if a.lower() in SHELL_CMD_FLAGS), None)
        if flag_idx is None:
            # e.g. `bash run.sh`: a script we cannot see.
            return [
                emit(
                    ctx,
                    "CFG-003",
                    affected=affected,
                    evidence=[(f"{server.json_path}.command", cmdline)],
                    description=f"Server '{server.name}' is launched through the shell `{shell}` "
                    "without an inline command; the real command lives in a script that this scan "
                    "cannot inspect.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                )
            ]
        flag = args[flag_idx].lower()
        payload = " ".join(args[flag_idx + 1 :])
        payload_path = (
            f"{server.json_path}.args[{flag_idx + 1}]"
            if flag_idx + 1 < len(args)
            else f"{server.json_path}.args"
        )
        if flag in ENCODED_FLAGS:
            return [
                emit(
                    ctx,
                    "CFG-003",
                    affected=affected,
                    evidence=[(payload_path, payload, "encoded command payload")],
                    description=f"Server '{server.name}' runs an *encoded* command through `{shell} "
                    f"{args[flag_idx]}`. Encoding hides the command from anyone reading the config.",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                )
            ]
        metas = find_metachars(payload)
        if metas:
            return [
                emit(
                    ctx,
                    "CFG-003",
                    affected=affected,
                    evidence=[(payload_path, payload, "shell metacharacters: " + " ".join(metas))],
                    description=f"Server '{server.name}' is launched via `{shell} {args[flag_idx]}` "
                    "and the payload contains shell metacharacters, so it can chain or redirect "
                    "commands beyond the visible server executable.",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                )
            ]
        # Plain single command behind a shell wrapper (common on Windows: `cmd /c npx ...`).
        return [
            emit(
                ctx,
                "CFG-003",
                affected=affected,
                evidence=[(payload_path, payload, "plain payload, no metacharacters")],
                description=f"Server '{server.name}' is wrapped in `{shell} {args[flag_idx]}` but the "
                "payload is a single plain command. This is a common Windows pattern; it is reported "
                "so the wrapper is reviewed, not because the payload itself is dangerous.",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
            )
        ]

    # Non-shell command: metacharacters in argv are inert for clients that spawn directly.
    hits = [(a, find_metachars(a.value)) for a in server.args if find_metachars(a.value)]
    if hits:
        return [
            emit(
                ctx,
                "CFG-003",
                affected=affected,
                evidence=[
                    (a.json_path, a.value, "metacharacters: " + " ".join(m)) for a, m in hits
                ],
                description=f"Arguments of server '{server.name}' contain shell metacharacters but the "
                "command is not a shell. Most MCP clients spawn the process directly, in which case "
                "these are harmless literals; a client that wraps commands in a shell would interpret "
                "them.",
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                kind=Kind.INFO,
            )
        ]
    return []
