from __future__ import annotations

from conftest import run_rule
from mcp_trustcheck.checks.config.filesystem import classify_path
from mcp_trustcheck.model import Severity

FS = "@modelcontextprotocol/server-filesystem@2026.1.0"


def _fs(*dirs: str) -> dict:  # type: ignore[type-arg]
    return {"mcpServers": {"fs": {"command": "npx", "args": ["-y", FS, *dirs]}}}


def test_classify_path() -> None:
    assert classify_path("/")[0] is Severity.HIGH  # type: ignore[index]
    assert classify_path("C:\\")[0] is Severity.HIGH  # type: ignore[index]
    assert classify_path("D:/")[0] is Severity.HIGH  # type: ignore[index]
    assert classify_path("~")[1] == "home directory"  # type: ignore[index]
    assert classify_path("/Users/alice/")[1] == "home directory"  # type: ignore[index]
    assert classify_path("C:\\Users\\alice")[1] == "home directory"  # type: ignore[index]
    assert classify_path("/home/bob/.ssh")[1].startswith("credential")  # type: ignore[index]
    assert classify_path("/etc")[1] == "system directory"  # type: ignore[index]
    assert classify_path("/Users/alice/Projects/app") is None
    assert classify_path("~/Documents/notes") is None
    assert classify_path("./data") is None


def test_root_and_home_positional() -> None:
    f = run_rule("CFG-006", _fs("/", "/Users/alice", "/Users/alice/Projects/app"))
    assert [(x.severity, x.evidence[0].snippet) for x in f] == [
        (Severity.HIGH, "/"),
        (Severity.MEDIUM, "/Users/alice"),
    ]


def test_flag_env_and_docker_forms() -> None:
    cfg = {
        "mcpServers": {
            "a": {"command": "uvx", "args": ["mcp-server-fs", "--root", "~/.aws"]},
            "b": {
                "command": "node",
                "args": ["server.js"],
                "env": {"ALLOWED_DIRS": "/etc:/Users/alice/proj"},
            },
            "c": {"command": "docker", "args": ["run", "-i", "-v", "/:/host:ro", "img"]},
            "d": {
                "command": "docker",
                "args": ["run", "--mount", "type=bind,source=/Users/bob,target=/data", "img"],
            },
        }
    }
    f = run_rule("CFG-006", cfg)
    got = {(x.affected.server, x.evidence[0].snippet) for x in f}
    assert got == {("a", "~/.aws"), ("b", "/etc"), ("c", "/"), ("d", "/Users/bob")}


def test_non_fs_server_with_paths_is_ignored() -> None:
    cfg = {
        "mcpServers": {"git": {"command": "uvx", "args": ["mcp-server-git", "--repository", "/"]}}
    }
    # '--repository' is not a directory-exposure flag and the package is not a filesystem server.
    assert run_rule("CFG-006", cfg) == []


def test_non_literal_dirs_are_ignored() -> None:
    assert run_rule("CFG-006", _fs("${workspaceFolder}", "$HOME")) == []
