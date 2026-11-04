"""CFG-009: plaintext transport to a remote server (threat-model.md T10)."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from mcp_trustcheck.checks import Context, emit, register
from mcp_trustcheck.checks._util import is_loopback_host, is_private_host
from mcp_trustcheck.model import Affected, Finding, ServerConfig, Severity
from mcp_trustcheck.redaction import looks_like_secret_key

_PLAIN = {"http", "ws"}


@register("CFG-009", "config")
def check_plaintext_transport(server: ServerConfig, ctx: Context) -> list[Finding]:
    if server.url is None or not server.url.literal:
        return []
    try:
        parts = urlsplit(server.url.value)
    except ValueError:
        return []
    if parts.scheme.lower() not in _PLAIN:
        return []
    host = parts.hostname
    if is_loopback_host(host):
        return []

    carries_credential = any(
        looks_like_secret_key(k) or k.lower() in ("authorization", "cookie", "x-api-key")
        for k in server.headers
    ) or bool(parts.password)
    private = is_private_host(host)
    sev = Severity.HIGH if carries_credential else Severity.MEDIUM
    notes = []
    if carries_credential:
        notes.append("request carries a credential header or URL credential")
    if private:
        notes.append("host is in a private/internal range; a protected network path may exist")
    desc = (
        f"Server '{server.name}' is reached over plaintext `{parts.scheme}://` at host `{host}`"
        + (", with a credential attached to every request" if carries_credential else "")
        + "."
    )
    return [
        emit(
            ctx,
            "CFG-009",
            affected=Affected(server.source_file, server.url.json_path, server=server.name),
            evidence=[(server.url.json_path, server.url.value, "; ".join(notes) or None)],
            description=desc,
            severity=sev,
        )
    ]


# ----------------------------------------------------------------------------- CFG-010


@register("CFG-010", "config")
def check_deprecated_transport(server: ServerConfig, ctx: Context) -> list[Finding]:
    if server.transport != "sse":
        return []
    path = server.url.json_path if server.url else server.json_path
    snippet = (
        server.url.value
        if server.url
        else str(server.raw.get("type") or server.raw.get("transport"))
    )
    return [
        emit(
            ctx,
            "CFG-010",
            affected=Affected(server.source_file, path, server=server.name),
            evidence=[(path, snippet, "legacy HTTP+SSE transport")],
            description=f"Server '{server.name}' uses the deprecated HTTP+SSE transport (protocol 2024-11-05).",
        )
    ]


# ----------------------------------------------------------------------------- CFG-011

_BIND_FLAGS = {
    "--host",
    "--bind",
    "--bind-address",
    "--listen",
    "--address",
    "--addr",
    "-H",
    "--hostname",
}
_BIND_ENV_RE = re.compile(
    r"(?i)^(?:[A-Z0-9_]*_)?(?:HOST|BIND|BIND_ADDR(?:ESS)?|LISTEN(?:_ADDR)?|ADDRESS|INTERFACE)$"
)
_ALL_IFACES = {"0.0.0.0", "::", "[::]", "*", "0.0.0.0:", "::0", "0", "any"}  # noqa: S104 - detector


def _is_all_interfaces(v: str) -> bool:
    host = v.strip().lower()
    host = re.sub(r":\d+$", "", host) if host.count(":") == 1 else host
    return host in _ALL_IFACES or host.startswith(("0.0.0.0", "[::]"))  # noqa: S104


def _has_auth_signal(server: ServerConfig) -> bool:
    keys = list(server.env) + [a.value for a in server.args]
    return any(
        looks_like_secret_key(k) or re.search(r"(?i)auth|oauth|jwt|bearer|api[-_]?key", k)
        for k in keys
    )


@register("CFG-011", "config")
def check_bind_all_interfaces(server: ServerConfig, ctx: Context) -> list[Finding]:
    if server.command is None:
        return []
    hits: list[tuple[str, str, str]] = []
    args = server.args
    for i, a in enumerate(args):
        if a.value in _BIND_FLAGS and i + 1 < len(args) and _is_all_interfaces(args[i + 1].value):
            hits.append((args[i + 1].json_path, f"{a.value} {args[i + 1].value}", "bind flag"))
        elif (
            "=" in a.value
            and a.value.split("=", 1)[0] in _BIND_FLAGS
            and _is_all_interfaces(a.value.split("=", 1)[1])
        ):
            hits.append((a.json_path, a.value, "bind flag"))
    for k, cv in server.env.items():
        if _BIND_ENV_RE.match(k) and cv.literal and _is_all_interfaces(cv.value):
            hits.append((cv.json_path, f"{k}={cv.value}", "bind environment variable"))
    if not hits:
        return []
    auth = _has_auth_signal(server)
    return [
        emit(
            ctx,
            "CFG-011",
            affected=Affected(server.source_file, hits[0][0], server=server.name),
            evidence=hits,
            description=f"Local server '{server.name}' is configured to listen on all network interfaces"
            + ("" if auth else " and no credential or auth setting is visible in its configuration")
            + ".",
            severity=Severity.MEDIUM if auth else Severity.HIGH,
        )
    ]


# ----------------------------------------------------------------------------- CFG-012

_AUTH_KEY_RE = re.compile(
    r"(?i)auth|oauth|token|credential|apikey|api[-_]key|bearer|client[-_]?id|secret"
)


@register("CFG-012", "config")
def check_no_auth_signal(server: ServerConfig, ctx: Context) -> list[Finding]:
    if server.url is None or not server.url.literal:
        return []
    try:
        host = urlsplit(server.url.value).hostname
    except ValueError:
        return []
    if is_loopback_host(host):
        return []
    if server.headers or any(_AUTH_KEY_RE.search(k) for k in server.raw):
        return []
    if urlsplit(server.url.value).username:
        return []
    return [
        emit(
            ctx,
            "CFG-012",
            affected=Affected(server.source_file, server.url.json_path, server=server.name),
            evidence=[
                (
                    server.url.json_path,
                    server.url.value,
                    "no headers or auth-related keys in the entry",
                )
            ],
            description=f"Remote server '{server.name}' has no authentication visible in its configuration. "
            "The client may still perform OAuth discovery at runtime; verify that it does.",
        )
    ]
