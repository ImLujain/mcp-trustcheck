"""CFG-006: over-broad filesystem access (threat-model.md T5)."""

from __future__ import annotations

import re

from mcp_trustcheck.checks import Context, emit, register
from mcp_trustcheck.model import Affected, Confidence, ConfigValue, Finding, ServerConfig, Severity

FS_PACKAGE_RE = re.compile(
    r"(?i)(?:server-filesystem|mcp[-_]?filesystem|filesystem[-_]?mcp|mcp[-_]?server[-_]?fs\b|"
    r"\bfs[-_]?mcp\b|file[-_]?server|mcp[-_]?fs\b|desktop[-_]?commander|filesystem)"
)
DIR_FLAG_RE = re.compile(
    r"(?i)^--?(?:allowed?[-_]?dir(?:ectory|ectories|s)?|root|roots|dir|directory|directories|"
    r"base[-_]?dir|workspace|path|paths|allow|mount)(?:=(.*))?$"
)
DIR_ENV_RE = re.compile(
    r"(?i)^(?:ALLOWED_(?:DIRS?|DIRECTORIES|PATHS?)|(?:FS|FILESYSTEM|MCP_FS|MCP)_?ROOTS?|ROOT_DIR|"
    r"BASE_DIR|WORKSPACE(?:_DIR|_ROOT)?|DIRECTORIES|DIRS)$"
)
VOLUME_FLAGS = {"-v", "--volume", "--mount"}

_DRIVE_ROOT = re.compile(r"^[A-Za-z]:[\\/]?$")
_WIN_HOME = re.compile(r"(?i)^[A-Za-z]:[\\/]Users(?:[\\/][^\\/]+)?[\\/]?$")
_HOME_TOKENS = {"~", "~/", "$home", "${home}", "%userprofile%", "%homepath%", "/users", "/home"}
_SYSTEM_DIRS = {
    "/etc",
    "/var",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/opt",
    "/system",
    "/library",
    "/private",
    "/root",
    "/proc",
    "/sys",
    "c:\\windows",
    "c:\\program files",
}
_CRED_DIR_RE = re.compile(
    r"(?i)(?:^|[\\/])\.(?:ssh|aws|gnupg|gpg|azure|config[\\/]gcloud|kube|docker|npmrc|netrc|"
    r"password-store|git-credentials|claude|cursor|codex)(?:$|[\\/])"
)


def _norm(path: str) -> str:
    p = path.strip().strip('"').strip("'")
    return p.rstrip("\\/") or p  # keep lone "/" and "C:\"


def classify_path(path: str) -> tuple[Severity, str] | None:
    p = _norm(path)
    low = p.lower()
    if low.endswith(".sock") or ("/run/" in low and "containerd" in low):
        return None  # runtime sockets are CFG-007's concern, not a directory exposure
    if p in ("/", "\\") or _DRIVE_ROOT.match(p):
        return (Severity.HIGH, "filesystem root")
    if low in _HOME_TOKENS or _WIN_HOME.match(p) or re.match(r"^/(?:users|home)/[^/]+$", low):
        return (Severity.MEDIUM, "home directory")
    if _CRED_DIR_RE.search(p):
        return (Severity.HIGH, "credential or client-config directory")
    if low in _SYSTEM_DIRS or any(
        low.startswith(d + "/") or low.startswith(d + "\\")
        for d in _SYSTEM_DIRS
        if d in ("/etc", "/var", "/usr", "/system", "/library", "/private", "/root", "c:\\windows")
    ):
        return (Severity.MEDIUM, "system directory")
    return None


def _looks_like_fs_server(server: ServerConfig) -> bool:
    text = " ".join([server.command or "", *server.arg_values])
    if FS_PACKAGE_RE.search(text):
        return True
    if any(DIR_FLAG_RE.match(a.value) for a in server.args):
        return True
    return any(DIR_ENV_RE.match(k) for k in server.env)


def _directory_values(server: ServerConfig) -> list[tuple[ConfigValue, str]]:
    """Return (value, how-it-was-identified) pairs that plausibly name exposed directories."""
    out: list[tuple[ConfigValue, str]] = []
    args = server.args
    is_container = any(
        a.value in VOLUME_FLAGS or a.value.startswith("--volume=") for a in args
    ) or (
        server.command is not None
        and server.command.lower().removesuffix(".exe").endswith(("docker", "podman", "nerdctl"))
    )
    i = 0
    while i < len(args):
        a = args[i]
        v = a.value
        if v in VOLUME_FLAGS and i + 1 < len(args):
            host = args[i + 1].value.split(":", 1)[0]
            if args[i + 1].value.startswith(("type=", "source=", "src=")):
                m = re.search(r"(?:source|src)=([^,]+)", args[i + 1].value)
                host = m.group(1) if m else host
            out.append(
                (ConfigValue(host, args[i + 1].literal, args[i + 1].json_path), "container volume")
            )
            i += 2
            continue
        if v.startswith("--volume="):
            out.append(
                (
                    ConfigValue(v.split("=", 1)[1].split(":", 1)[0], a.literal, a.json_path),
                    "container volume",
                )
            )
        m = DIR_FLAG_RE.match(v)
        if m:
            if m.group(1) is not None:
                out.append(
                    (ConfigValue(m.group(1), a.literal, a.json_path), f"flag {v.split('=', 1)[0]}")
                )
            elif i + 1 < len(args):
                out.append((args[i + 1], f"flag {v}"))
                i += 2
                continue
        elif (
            not is_container
            and not v.startswith("-")
            and _is_pathlike(v)
            and _after_package(server, i)
        ):
            out.append((a, "positional directory"))
        i += 1
    for k, ev in server.env.items():
        if DIR_ENV_RE.match(k):
            for part in _split_path_list(ev.value):
                out.append((ConfigValue(part, ev.literal, ev.json_path), f"env {k}"))
    return out


def _split_path_list(value: str) -> list[str]:
    """Split PATH-style lists; colons are separators unless the value is a Windows drive path."""
    sep = r"[;,]" if re.match(r"^[A-Za-z]:[\\/]", value) else r"[;:,]"
    return [p for p in (x.strip() for x in re.split(sep, value)) if p]


def _is_pathlike(v: str) -> bool:
    return (
        v in ("/", "~", "\\")
        or v.startswith(("/", "~", "$", "%", ".", "\\"))
        or bool(re.match(r"^[A-Za-z]:[\\/]", v))
    )


def _after_package(server: ServerConfig, idx: int) -> bool:
    """Positional dirs only count once the package/script name has been seen (npx -y pkg DIR...)."""
    args = server.arg_values[:idx]
    if server.command and re.search(
        r"(?i)(?:^|[\\/])(?:npx|uvx|bunx|pipx|node|python3?|deno)(?:\.exe)?$", server.command
    ):
        return any(not a.startswith("-") for a in args)
    return True


@register("CFG-006", "config")
def check_filesystem_scope(server: ServerConfig, ctx: Context) -> list[Finding]:
    if not _looks_like_fs_server(server) and not any(
        h == "container volume" for _, h in _directory_values(server)
    ):
        return []
    findings: list[Finding] = []
    seen: set[str] = set()
    for cv, how in _directory_values(server):
        if not cv.literal or cv.json_path in seen:
            continue
        hit = classify_path(cv.value)
        if hit is None:
            continue
        seen.add(cv.json_path)
        sev, label = hit
        findings.append(
            emit(
                ctx,
                "CFG-006",
                affected=Affected(server.source_file, cv.json_path, server=server.name),
                evidence=[(cv.json_path, cv.value, f"{label}; identified via {how}")],
                description=f"Server '{server.name}' exposes a {label} (`{cv.value}`) to a filesystem-capable "
                "tool. Everything beneath it becomes reachable by the model.",
                severity=sev,
                confidence=Confidence.HIGH
                if how.startswith(("flag", "env", "container"))
                else Confidence.MEDIUM,
                key=cv.json_path,
            )
        )
    return findings
