from __future__ import annotations

from conftest import run_rule
from mcp_trustcheck.model import Kind, Severity


def _cfg(entry: dict) -> dict:  # type: ignore[type-arg]
    return {"mcpServers": {"s": entry}}


def test_cfg007_flags() -> None:
    f = run_rule("CFG-007", _cfg({"command": "docker", "args": ["run", "--privileged", "img"]}))
    assert f[0].severity is Severity.HIGH and "privileged" in f[0].evidence[0].snippet
    f = run_rule(
        "CFG-007",
        _cfg(
            {
                "command": "podman",
                "args": [
                    "run",
                    "--network",
                    "host",
                    "--pid=host",
                    "--cap-add",
                    "SYS_ADMIN",
                    "--security-opt",
                    "apparmor=unconfined",
                    "-u",
                    "root:root",
                    "-v",
                    "/run/podman/podman.sock:/s",
                    "img",
                ],
            }
        ),
    )
    assert len(f) == 1 and len(f[0].evidence) == 6
    assert (
        run_rule(
            "CFG-007",
            _cfg(
                {
                    "command": "docker",
                    "args": [
                        "run",
                        "--cap-drop",
                        "ALL",
                        "--cap-add",
                        "NET_BIND_SERVICE",
                        "--network",
                        "bridge",
                        "img",
                    ],
                }
            ),
        )
        == []
    )
    assert (
        run_rule("CFG-007", _cfg({"command": "docker", "args": ["compose", "up", "--privileged"]}))
        == []
    )
    assert run_rule("CFG-007", _cfg({"command": "npx", "args": ["--privileged"]})) == []


def test_cfg008_env_classes() -> None:
    f = run_rule(
        "CFG-008",
        _cfg(
            {
                "command": "x",
                "env": {
                    "LD_PRELOAD": "/x.so",
                    "PYTHONPATH": "/p",
                    "NODE_OPTIONS": "--max-old-space-size=4096",
                    "LOG_LEVEL": "debug",
                },
            }
        ),
    )
    sev = {x.evidence[0].snippet.split("=")[0]: x.severity for x in f}
    assert sev == {
        "LD_PRELOAD": Severity.HIGH,
        "PYTHONPATH": Severity.MEDIUM,
        "NODE_OPTIONS": Severity.MEDIUM,
    }
    f = run_rule("CFG-008", _cfg({"command": "x", "env": {"NODE_OPTIONS": "--require /hook.js"}}))
    assert f[0].severity is Severity.HIGH


def test_cfg010_sse() -> None:
    assert (
        run_rule("CFG-010", _cfg({"type": "sse", "url": "https://h/x"}))[0].severity is Severity.LOW
    )
    assert run_rule("CFG-010", _cfg({"url": "https://h/sse"}))[0].severity is Severity.LOW
    assert run_rule("CFG-010", _cfg({"url": "https://h/mcp"})) == []
    assert run_rule("CFG-010", _cfg({"type": "http", "url": "https://h/sse"})) == []


def test_cfg011_bind() -> None:
    assert (
        run_rule("CFG-011", _cfg({"command": "uvx", "args": ["p==1", "--host", "0.0.0.0"]}))[
            0
        ].severity
        is Severity.HIGH
    )
    assert (
        run_rule(
            "CFG-011",
            _cfg(
                {
                    "command": "uvx",
                    "args": ["p==1", "--host=0.0.0.0"],
                    "env": {"API_KEY": "${env:K}"},
                }
            ),
        )[0].severity
        is Severity.MEDIUM
    )
    assert (
        run_rule("CFG-011", _cfg({"command": "node", "args": ["s.js"], "env": {"HOST": "[::]"}}))[
            0
        ].severity
        is Severity.HIGH
    )
    assert run_rule(
        "CFG-011",
        _cfg({"command": "node", "args": ["s.js"], "env": {"FASTMCP_HOST": "0.0.0.0:8000"}}),
    )
    assert (
        run_rule("CFG-011", _cfg({"command": "uvx", "args": ["p==1", "--host", "127.0.0.1"]})) == []
    )
    assert (
        run_rule(
            "CFG-011", _cfg({"command": "node", "args": ["s.js"], "env": {"HOST": "${env:HOST}"}})
        )
        == []
    )
    assert (
        run_rule("CFG-011", _cfg({"url": "http://0.0.0.0:8000/mcp"})) == []
    )  # remote entries are CFG-009's domain


def test_cfg012_info_only_when_nothing_visible() -> None:
    f = run_rule("CFG-012", _cfg({"url": "https://h.example.com/mcp"}))
    assert f[0].severity is Severity.INFO and f[0].kind is Kind.INFO
    assert (
        run_rule(
            "CFG-012",
            _cfg({"url": "https://h.example.com/mcp", "headers": {"X-Api-Key": "${env:K}"}}),
        )
        == []
    )
    assert (
        run_rule("CFG-012", _cfg({"url": "https://h.example.com/mcp", "oauth": {"clientId": "x"}}))
        == []
    )
    assert run_rule("CFG-012", _cfg({"url": "http://localhost:3000/mcp"})) == []


def test_cfg014_duplicates_within_file_only() -> None:
    cfg = {
        "mcpServers": {
            "a": {"command": "npx", "args": ["-y", "p@1"]},
            "b": {"command": "npx", "args": ["-y", "p@1"]},
            "c": {"url": "https://h/mcp"},
            "d": {"url": "https://h/mcp/"},
            "e": {"command": "npx", "args": ["-y", "q@1"]},
        }
    }
    f = run_rule("CFG-014", cfg)
    assert {x.affected.server for x in f} == {"b", "d"}
    assert all(x.kind is Kind.INFO for x in f)
