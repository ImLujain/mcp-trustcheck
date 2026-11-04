"""CFG-004: dangerous command content in a server launch line (threat-model.md T6)."""

from __future__ import annotations

import re
from dataclasses import dataclass

from mcp_trustcheck.checks import Context, emit, register
from mcp_trustcheck.model import Affected, Finding, ServerConfig, Severity


@dataclass(frozen=True)
class Pattern:
    name: str
    regex: re.Pattern[str]
    severity: Severity


PATTERNS: tuple[Pattern, ...] = (
    Pattern(
        "download-to-shell",
        re.compile(
            r"(?:curl|wget|Invoke-WebRequest|iwr)\b[^|;&]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|\biex\b|Invoke-Expression|DownloadString\("
        ),
        Severity.CRITICAL,
    ),
    Pattern(
        "reverse-shell",
        re.compile(
            r"/dev/tcp/|\bnc\b[^|;&]*\s-e\s|\bncat\b[^|;&]*--exec|\bsocat\b[^|;&]*exec:|\bbash\s+-i\b"
        ),
        Severity.CRITICAL,
    ),
    Pattern(
        "privilege-escalation",
        re.compile(r"(?:^|[\s;&|])(?:sudo|doas|pkexec|runas)\b"),
        Severity.CRITICAL,
    ),
    Pattern(
        "decode-and-run",
        re.compile(
            r"base64\s+(?:-d|--decode)[^|;&]*\|\s*(?:ba|z)?sh\b|certutil\s+-decode|\bmshta\b|-w(?:indowstyle)?\s+hidden"
        ),
        Severity.CRITICAL,
    ),
    Pattern(
        "destructive-delete",
        re.compile(
            r"\brm\s+-[a-zA-Z]*[rf][a-zA-Z]*\s+(?:/|~|\$HOME|\*|\.)|\bdel\s+/[sq]\b|\brmdir\s+/s\b|\bformat\s+[a-zA-Z]:|\bmkfs\b|\bdd\s+if=.*of=/dev/"
        ),
        Severity.HIGH,
    ),
    Pattern(
        "credential-path",
        re.compile(
            r"(?:~|\$HOME|/Users/[^/\s]+|/home/[^/\s]+|%USERPROFILE%)?[\\/]\.(?:ssh|aws|gnupg|kube|docker|netrc|npmrc|git-credentials|bash_history|zsh_history)\b|\bid_(?:rsa|ed25519|ecdsa)\b|/etc/(?:shadow|sudoers)|\bkeychain\b|Login\.keychain"
        ),
        Severity.HIGH,
    ),
    Pattern(
        "persistence",
        re.compile(
            r"\bcrontab\b|/etc/cron|LaunchAgents|LaunchDaemons|\bschtasks\b|\breg\s+add\b.*\\Run\b|\.bashrc\b|\.zshrc\b|\.profile\b"
        ),
        Severity.HIGH,
    ),
    Pattern(
        "network-exfil",
        re.compile(
            r"(?:curl|wget)\b[^|;&]*(?:-d\s*@|--data(?:-binary)?\s*@|-T\s|--upload-file\s|-F\s)"
        ),
        Severity.HIGH,
    ),
)


@register("CFG-004", "config")
def check_dangerous_content(server: ServerConfig, ctx: Context) -> list[Finding]:
    if not server.command:
        return []
    line = server.command_line
    findings: list[Finding] = []
    for pat in PATTERNS:
        m = pat.regex.search(line)
        if not m:
            continue
        # Locate the argument that contains the match for a precise json_path.
        path = f"{server.json_path}.command"
        for a in server.args:
            if m.group(0).strip() and m.group(0).strip() in a.value:
                path = a.json_path
                break
        findings.append(
            emit(
                ctx,
                "CFG-004",
                affected=Affected(server.source_file, path, server=server.name),
                evidence=[(path, line, f"pattern: {pat.name} (`{m.group(0).strip()}`)")],
                description=f"The launch command of server '{server.name}' contains a {pat.name} idiom.",
                severity=pat.severity,
                key=pat.name,
            )
        )
    return findings
