"""CFG-005: hardcoded credentials (threat-model.md T9)."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

from mcp_trustcheck.checks import Context, emit, register
from mcp_trustcheck.model import Affected, Confidence, ConfigValue, Finding, ServerConfig, Severity
from mcp_trustcheck.redaction import (
    Redactor,
    is_placeholder,
    looks_like_secret_key,
    match_known_pattern,
    redact,
    shannon_entropy,
)

_FLAG_SECRET_RE = re.compile(
    r"(?i)^--?(?:[a-z0-9_-]*)(?:token|secret|key|password|passwd|pwd|auth)[a-z0-9_-]*$"
)
_KV_RE = re.compile(r"^([A-Za-z0-9_.-]+)=(.*)$")
_BEARER_RE = re.compile(r"(?i)^\s*(?:bearer|basic|token)\s+(\S+)")

# (json_path, key_hint, value, origin)
Candidate = tuple[str, str, str, str]


def _url_candidates(url: ConfigValue) -> list[Candidate]:
    out: list[Candidate] = []
    try:
        parts = urlsplit(url.value)
    except ValueError:
        return out
    if parts.password:
        out.append((url.json_path, "password", parts.password, "url userinfo"))
    for k, v in parse_qsl(parts.query, keep_blank_values=False):
        out.append((url.json_path, k, v, f"url query parameter '{k}'"))
    return out


def _arg_candidates(server: ServerConfig) -> list[Candidate]:
    out: list[Candidate] = []
    args = server.args
    for i, a in enumerate(args):
        if not a.literal:
            continue
        m = _KV_RE.match(a.value)
        if m:
            out.append((a.json_path, m.group(1), m.group(2), f"argument '{m.group(1)}='"))
            continue
        if _FLAG_SECRET_RE.match(a.value) and i + 1 < len(args) and args[i + 1].literal:
            nxt = args[i + 1]
            out.append((nxt.json_path, a.value, nxt.value, f"value after flag '{a.value}'"))
        else:
            out.append((a.json_path, "", a.value, "argument"))
    return out


def _header_value(v: str) -> str:
    m = _BEARER_RE.match(v)
    return m.group(1) if m else v


def candidates(server: ServerConfig) -> list[Candidate]:
    out: list[Candidate] = []
    for k, v in server.env.items():
        if v.literal:
            out.append((v.json_path, k, v.value, f"env '{k}'"))
    for k, v in server.headers.items():
        if v.literal:
            out.append((v.json_path, k, _header_value(v.value), f"header '{k}'"))
    if server.url and server.url.literal:
        out.extend(_url_candidates(server.url))
    out.extend(_arg_candidates(server))
    return out


_ENTROPY_ORIGINS = ("env ", "header ", "url query")
_TOKEN_SHAPE_RE = re.compile(r"^[A-Za-z0-9_\-+=./]{24,}$")


def classify(key: str, value: str, origin: str = "env") -> tuple[str, Confidence, Severity] | None:
    """Return (detector name, confidence, severity) or None if not a secret.

    Known prefixes are trusted anywhere. Key-name matches need a key. The entropy heuristic is only
    applied to env/header/URL-query values that are shaped like a token: bare arguments are full of
    high-entropy non-secrets (package specs, paths, regexes), which made it a false-positive source.
    """
    if is_placeholder(value) or len(value) < 8:
        return None
    pat = match_known_pattern(value)
    if pat:
        return (pat.name, Confidence.HIGH, Severity.CRITICAL if pat.critical else Severity.HIGH)
    if key and looks_like_secret_key(key):
        return ("secret-like key name", Confidence.MEDIUM, Severity.HIGH)
    if (
        origin.startswith(_ENTROPY_ORIGINS)
        and _TOKEN_SHAPE_RE.match(value)
        and value.count("/") <= 2
        and not value.startswith(("/", "~", ".", "@"))
        and shannon_entropy(value) >= 4.0
    ):
        return ("high-entropy value", Confidence.LOW, Severity.MEDIUM)
    return None


def collect_sensitive_values(servers: list[ServerConfig], redactor: Redactor) -> None:
    """Pre-pass used by the scanner so *every* finding's evidence is scrubbed, not just CFG-005's."""
    for s in servers:
        for _path, key, value, _origin in candidates(s):
            if classify(key, value, _origin) is not None:
                redactor.add(value)


@register("CFG-005", "config")
def check_hardcoded_secrets(server: ServerConfig, ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for path, key, value, origin in candidates(server):
        hit = classify(key, value, origin)
        if hit is None or (path, value) in seen:
            continue
        seen.add((path, value))
        name, conf, sev = hit
        ctx.redactor.add(value)
        findings.append(
            emit(
                ctx,
                "CFG-005",
                affected=Affected(server.source_file, path, server=server.name),
                evidence=[(path, redact(value), f"detector: {name}; location: {origin}")],
                description=f"Server '{server.name}' stores what appears to be a credential in plaintext "
                f"({origin}; matched by {name}).",
                severity=sev,
                confidence=conf,
                key=redact(value),
            )
        )
    return findings
