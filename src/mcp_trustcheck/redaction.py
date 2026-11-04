"""Secret detection patterns and redaction.

Redaction is applied when a Finding is constructed (see checks.emit), never at output time,
so there is no code path by which a raw secret reaches a renderer or a log line.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

SNIPPET_MAX = 512


@dataclass(frozen=True)
class SecretPattern:
    name: str
    regex: re.Pattern[str]
    critical: bool = False  # cloud root / payment / private key material


# Known-prefix detectors. Ordered roughly by specificity. All are case-sensitive on purpose.
SECRET_PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), critical=True),
    SecretPattern("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), critical=True),
    SecretPattern("stripe-live-key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{16,}\b"), critical=True),
    SecretPattern("anthropic-api-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    SecretPattern("openai-style-key", re.compile(r"\bsk-(?!ant-)[A-Za-z0-9_-]{20,}")),
    SecretPattern("github-token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b")),
    SecretPattern("github-fine-grained-pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    SecretPattern("gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    SecretPattern("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    SecretPattern("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    SecretPattern("npm-token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    SecretPattern("huggingface-token", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    SecretPattern("notion-token", re.compile(r"\bntn_[A-Za-z0-9]{40,}\b")),
    SecretPattern("supabase-token", re.compile(r"\bsbp_[0-9a-f]{40}\b")),
    SecretPattern("linear-api-key", re.compile(r"\blin_api_[A-Za-z0-9]{30,}\b")),
    SecretPattern(
        "jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
    ),
    SecretPattern("sendgrid-key", re.compile(r"\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b")),
)

# Key names that strongly suggest the value is a credential.
SECRET_KEY_RE = re.compile(
    r"(?i)(?:^|[_\-.\s])(?:token|secret|passw(?:or)?d|pwd|api[_-]?key|apikey|auth(?:orization)?"
    r"|credential[s]?|private[_-]?key|access[_-]?key|client[_-]?secret|bearer|session[_-]?key)"
    r"(?:$|[_\-.\s])"
)

# Values that are obviously not real secrets.
PLACEHOLDER_RE = re.compile(
    r"(?i)^\s*(?:<[^>]*>|\[[^\]]*\]|\{\{[^}]*\}\}|your[-_ ]|my[-_ ]|xxx+|\*{3,}|\.{3,}|change[-_ ]?me"
    r"|replace[-_ ]?me|todo|tbd|placeholder|dummy|example|sample|test[-_]?key|none|null|undefined)"
)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_placeholder(value: str) -> bool:
    v = value.strip()
    return not v or bool(PLACEHOLDER_RE.match(v)) or len(set(v)) <= 2


def match_known_pattern(value: str) -> SecretPattern | None:
    for pat in SECRET_PATTERNS:
        if pat.regex.search(value):
            return pat
    return None


def looks_like_secret_key(key: str) -> bool:
    return bool(SECRET_KEY_RE.search(key))


_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def sanitize_controls(text: str) -> str:
    """Make C0/C1 control characters visible (`\x1b` -> `\\x1b`) so untrusted strings cannot drive a terminal.

    Tabs and newlines are left alone here; renderers decide how to show them.
    """
    return _CONTROL_RE.sub(lambda m: f"\\x{ord(m.group(0)):02x}", text)


def redact(value: str, keep: int = 4) -> str:
    """`sk-abc...` -> `sk-a…[redacted 44 chars]`. Short values keep nothing."""
    n = len(value)
    if n <= 8:
        return f"[redacted {n} chars]"
    return f"{value[:keep]}…[redacted {n - keep} chars]"


class Redactor:
    """Holds every value the scan has classified as sensitive and scrubs it out of text."""

    def __init__(self) -> None:
        self._values: set[str] = set()

    def add(self, value: str) -> None:
        if len(value) >= 6:
            self._values.add(value)

    def __len__(self) -> int:
        return len(self._values)

    def scrub(self, text: str) -> str:
        for v in sorted(self._values, key=len, reverse=True):
            if v in text:
                text = text.replace(v, redact(v))
        return sanitize_controls(text)

    def snippet(self, text: str) -> str:
        """Scrub, collapse whitespace, and cap to the schema's maximum length."""
        out = " ".join(self.scrub(text).split())
        if len(out) > SNIPPET_MAX:
            out = out[: SNIPPET_MAX - 1] + "…"
        return out
