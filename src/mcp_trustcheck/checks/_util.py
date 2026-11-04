"""Shared helpers: loopback/private host detection, shell detection, snippet helpers."""

from __future__ import annotations

import ipaddress
import re
from pathlib import PureWindowsPath
from urllib.parse import urlsplit

SHELLS = frozenset(
    {
        "sh",
        "bash",
        "zsh",
        "dash",
        "ksh",
        "fish",
        "ash",
        "cmd",
        "cmd.exe",
        "powershell",
        "powershell.exe",
        "pwsh",
        "pwsh.exe",
        "command.com",
    }
)
SHELL_CMD_FLAGS = frozenset(
    {"-c", "/c", "/k", "-command", "-c:", "-encodedcommand", "-enc", "-e", "-ec"}
)
ENCODED_FLAGS = frozenset({"-encodedcommand", "-enc", "-e", "-ec"})

# Characters/sequences that a POSIX shell or cmd.exe would interpret.
METACHAR_RE = re.compile(r"(&&|\|\||;|\||\$\(|`|>>|>|<|\n|\r|%[A-Za-z_]+%)")


def basename(command: str) -> str:
    """Case-insensitive basename of a command, handling both separators and `.exe`."""
    name = PureWindowsPath(command.replace("/", "\\")).name.lower()
    return name


def is_shell(command: str | None) -> bool:
    return command is not None and basename(command) in SHELLS


def find_metachars(text: str) -> list[str]:
    return sorted({m.group(0) for m in METACHAR_RE.finditer(text)})


def host_of(url: str) -> str | None:
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    return parts.hostname


def is_loopback_host(host: str | None) -> bool:
    if not host:
        return False
    h = host.lower().strip("[]")
    if h == "localhost" or h.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_unspecified


def is_private_host(host: str | None) -> bool:
    if not host:
        return False
    h = host.lower().strip("[]")
    if h.endswith((".local", ".internal", ".lan", ".home", ".corp", ".intranet")):
        return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    return ip.is_private or ip.is_link_local
