from __future__ import annotations

from conftest import run_rule
from mcp_trustcheck.model import Severity


def _url(url: str, headers: dict[str, str] | None = None) -> dict:  # type: ignore[type-arg]
    entry: dict[str, object] = {"url": url}
    if headers:
        entry["headers"] = headers
    return {"mcpServers": {"r": entry}}


def test_plaintext_remote_medium_and_with_credential_high() -> None:
    assert run_rule("CFG-009", _url("http://mcp.example.com/mcp"))[0].severity is Severity.MEDIUM
    f = run_rule(
        "CFG-009", _url("http://mcp.example.com/mcp", {"Authorization": "Bearer ${env:T}"})
    )
    assert f[0].severity is Severity.HIGH
    assert run_rule("CFG-009", _url("ws://mcp.example.com/ws"))[0].severity is Severity.MEDIUM


def test_loopback_and_tls_are_clean() -> None:
    for u in (
        "http://localhost:3000/mcp",
        "http://127.0.0.1/mcp",
        "http://[::1]:8/mcp",
        "http://app.localhost/",
        "https://mcp.example.com/mcp",
        "wss://x.example.com",
        "${env:MCP_URL}",
    ):
        assert run_rule("CFG-009", _url(u)) == [], u


def test_private_host_is_noted() -> None:
    f = run_rule("CFG-009", _url("http://10.4.2.17:8080/mcp"))
    assert "private" in (f[0].evidence[0].note or "")


def _approval(entry: dict[str, object]) -> dict:  # type: ignore[type-arg]
    return {"mcpServers": {"s": {"command": "x", **entry}}}


def test_wildcards_are_high_and_lists_medium() -> None:
    assert run_rule("CFG-013", _approval({"autoApprove": ["*"]}))[0].severity is Severity.HIGH
    assert run_rule("CFG-013", _approval({"alwaysAllow": True}))[0].severity is Severity.HIGH
    assert run_rule("CFG-013", _approval({"trust": True}))[0].severity is Severity.HIGH
    f = run_rule("CFG-013", _approval({"autoApprove": ["read_note", "list_notes"]}))
    assert f[0].severity is Severity.MEDIUM and "read_note" in f[0].description


def test_no_approval_keys_or_disabled_server_is_clean() -> None:
    assert run_rule("CFG-013", _approval({})) == []
    assert run_rule("CFG-013", _approval({"autoApprove": []})) == []
    assert run_rule("CFG-013", _approval({"trust": False})) == []
    assert run_rule("CFG-013", _approval({"autoApprove": ["*"], "disabled": True})) == []
