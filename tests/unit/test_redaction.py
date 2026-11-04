from __future__ import annotations

from mcp_trustcheck.redaction import (
    SNIPPET_MAX,
    Redactor,
    is_placeholder,
    looks_like_secret_key,
    match_known_pattern,
    redact,
    shannon_entropy,
)


def test_redact_keeps_short_prefix_only() -> None:
    assert redact("sk-FAKE000000000000000000000000000000000000FAKE") == "sk-F…[redacted 43 chars]"
    assert redact("short") == "[redacted 5 chars]"
    assert "FAKE" not in redact("ghp_FAKE0000000000000000000000000000FAKE")


def test_known_patterns() -> None:
    assert match_known_pattern("AKIAIOSFODNN7EXAMPLE").name == "aws-access-key-id"  # type: ignore[union-attr]
    assert match_known_pattern("ghp_FAKE0000000000000000000000000000FAKE").name == "github-token"  # type: ignore[union-attr]
    assert match_known_pattern("sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKE").name == "anthropic-api-key"  # type: ignore[union-attr]
    assert match_known_pattern("@modelcontextprotocol/server-filesystem@2026.1.0") is None
    assert match_known_pattern("sk-ant") is None


def test_placeholders_and_keys() -> None:
    for v in ("", "<your-api-key>", "YOUR_TOKEN_HERE", "xxxxxxxxxxxx", "changeme", "...", "***"):
        assert is_placeholder(v), v
    assert not is_placeholder("correct-horse-battery-staple-9")
    assert looks_like_secret_key("GITHUB_PERSONAL_ACCESS_TOKEN")
    assert looks_like_secret_key("db-password")
    assert looks_like_secret_key("Authorization")
    assert not looks_like_secret_key("ALLOWED_DIRS")
    assert not looks_like_secret_key("tokenizer_model")  # 'token' not on a word boundary


def test_entropy() -> None:
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaaaaaa") == 0.0
    assert shannon_entropy("abcdefghijklmnop") > 3.9


def test_redactor_scrubs_and_caps() -> None:
    r = Redactor()
    secret = "ghp_FAKE0000000000000000000000000000FAKE"
    r.add(secret)
    r.add("tiny")  # ignored: too short to scrub safely
    out = r.snippet(f"Authorization: Bearer {secret} " + "x" * 2000)
    assert secret not in out
    assert "ghp_…[redacted" in out
    assert len(out) <= SNIPPET_MAX
    assert out.endswith("…")
