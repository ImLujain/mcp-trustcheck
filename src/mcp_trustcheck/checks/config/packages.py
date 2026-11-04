"""CFG-001 unpinned package launch; CFG-002 unexpected executable / inline interpreter code."""

from __future__ import annotations

import re

from mcp_trustcheck.checks import Context, emit, register
from mcp_trustcheck.checks._util import basename
from mcp_trustcheck.model import Affected, Confidence, Finding, ServerConfig, Severity

# launcher basename -> ecosystem
LAUNCHERS = {
    "npx": "npm",
    "bunx": "npm",
    "uvx": "pypi",
    "pipx": "pypi",
    "pnpm": "npm",
    "yarn": "npm",
}
NPM_SKIP_FLAGS = {
    "-y",
    "--yes",
    "-q",
    "--quiet",
    "--no-install",
    "--prefer-offline",
    "--ignore-existing",
}
NPM_VALUE_FLAGS = {"-p", "--package", "--registry", "--cache"}
UV_VALUE_FLAGS = {
    "--from",
    "--with",
    "--python",
    "-p",
    "--index",
    "--index-url",
    "--extra-index-url",
}

_NPM_SPEC = re.compile(r"^(?P<name>@[^/@]+/[^@]+|[^@][^@]*)(?:@(?P<ver>.+))?$")
_PY_SPEC = re.compile(
    r"^(?P<name>[A-Za-z0-9_.\-]+(?:\[[^\]]*\])?)(?P<spec>(?:==|@|===|>=|<=|~=|!=|>|<).*)?$"
)
_EXACT_NPM = re.compile(r"^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?$")
_EXACT_PY = re.compile(r"^(?:==|===|@)\s*v?\d+(?:\.\d+)*(?:[a-zA-Z0-9.+\-]*)$")
_GIT_SHA = re.compile(r"#[0-9a-f]{7,40}$|@[0-9a-f]{40}$")
_GIT_URL = re.compile(r"^(?:git\+|github:|gitlab:|bitbucket:|https?://|git@|ssh://)")

TRANSIENT_DIR_RE = re.compile(
    r"(?i)(?:^|[\\/])(?:tmp|temp|var[\\/]tmp|private[\\/]tmp|Downloads|Desktop|AppData[\\/]Local[\\/]Temp|"
    r"\.cache|Caches|Trash|\.Trash)(?:[\\/]|$)"
)
INTERPRETERS = {
    "python",
    "python3",
    "python2",
    "node",
    "nodejs",
    "deno",
    "bun",
    "ruby",
    "perl",
    "php",
}
INLINE_FLAGS = {"-c", "-e", "--eval", "-p", "--print", "-r", "--input-type=module"}


def package_spec(server: ServerConfig) -> tuple[str, str, int] | None:
    """Return (ecosystem, spec, arg_index) for the package a launcher will resolve, or None."""
    if not server.command:
        return None
    launcher = basename(server.command).removesuffix(".exe").removesuffix(".cmd")
    eco = LAUNCHERS.get(launcher)
    if eco is None:
        return None
    args = server.arg_values
    i = 0
    if launcher in ("pnpm", "yarn"):
        if not args or args[0] not in ("dlx", "exec", "x"):
            return None
        i = 1
    if launcher == "pipx":
        if not args or args[0] != "run":
            return None
        i = 1
    while i < len(args):
        a = args[i]
        if eco == "npm" and a in NPM_VALUE_FLAGS and i + 1 < len(args):
            return (eco, args[i + 1], i + 1)  # `npx -p pkg cmd`: the package is the -p value
        if eco == "pypi" and a == "--from" and i + 1 < len(args):
            return (eco, args[i + 1], i + 1)
        if a.startswith("--from="):
            return (eco, a.split("=", 1)[1], i)
        if a in NPM_SKIP_FLAGS or (eco == "pypi" and a in UV_VALUE_FLAGS and i + 1 < len(args)):
            i += 2 if a in UV_VALUE_FLAGS else 1
            continue
        if a.startswith("-"):
            i += 1
            continue
        return (eco, a, i)
    return None


def is_pinned(eco: str, spec: str) -> tuple[bool, str]:
    """Return (pinned, reason)."""
    if _GIT_URL.match(spec):
        return (
            bool(_GIT_SHA.search(spec)),
            "git reference" + ("" if _GIT_SHA.search(spec) else " without commit SHA"),
        )
    if spec.startswith((".", "/", "~")) or re.match(r"^[A-Za-z]:[\\/]", spec):
        return (True, "local path")
    if eco == "npm":
        m = _NPM_SPEC.match(spec)
        ver = m.group("ver") if m else None
        if not ver:
            return (False, "no version")
        return (
            bool(_EXACT_NPM.match(ver)),
            f"version '{ver}'" + ("" if _EXACT_NPM.match(ver) else " is a range or tag"),
        )
    m = _PY_SPEC.match(spec)
    sp = m.group("spec") if m else None
    if not sp:
        return (False, "no version")
    return (
        bool(_EXACT_PY.match(sp)),
        f"specifier '{sp}'" + ("" if _EXACT_PY.match(sp) else " is not an exact pin"),
    )


@register("CFG-001", "config")
def check_unpinned_package(server: ServerConfig, ctx: Context) -> list[Finding]:
    found = package_spec(server)
    if found is None:
        return []
    eco, spec, idx = found
    if not server.args[idx].literal:
        return []
    pinned, reason = is_pinned(eco, spec)
    if pinned:
        return []
    path = server.args[idx].json_path
    return [
        emit(
            ctx,
            "CFG-001",
            affected=Affected(server.source_file, path, server=server.name),
            evidence=[(path, spec, reason)],
            description=f"Server '{server.name}' launches `{spec}` through `{basename(server.command or '')}` "
            f"without an exact version ({reason}); whichever release the registry serves next is what runs.",
        )
    ]


@register("CFG-002", "config")
def check_unexpected_executable(server: ServerConfig, ctx: Context) -> list[Finding]:
    if not server.command:
        return []
    findings: list[Finding] = []
    cmd = server.command
    affected = Affected(server.source_file, f"{server.json_path}.command", server=server.name)
    if TRANSIENT_DIR_RE.search(cmd):
        findings.append(
            emit(
                ctx,
                "CFG-002",
                affected=affected,
                evidence=[
                    (f"{server.json_path}.command", cmd, "transient or user-writable location")
                ],
                description=f"Server '{server.name}' runs an executable from a temporary, download or cache "
                "location, where it can be replaced without any change to this config.",
            )
        )
    name = basename(cmd).removesuffix(".exe")
    base = re.sub(r"\d+(?:\.\d+)*$", "", name) if name.startswith("python") else name
    if base in INTERPRETERS:
        for i, a in enumerate(server.arg_values):
            if a in INLINE_FLAGS and i + 1 < len(server.arg_values):
                payload = server.args[i + 1]
                findings.append(
                    emit(
                        ctx,
                        "CFG-002",
                        affected=Affected(
                            server.source_file, payload.json_path, server=server.name
                        ),
                        evidence=[
                            (payload.json_path, payload.value, f"inline program via `{name} {a}`")
                        ],
                        description=f"Server '{server.name}' is an inline `{name} {a}` program embedded in the "
                        "config entry rather than a reviewable file.",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        key="inline",
                    )
                )
                break
    return findings
