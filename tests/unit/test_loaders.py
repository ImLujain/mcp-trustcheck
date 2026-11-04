from __future__ import annotations

from conftest import servers_from, toolset_from
from mcp_trustcheck.loaders import detect_kind
from mcp_trustcheck.loaders.refs import is_literal


def test_detect_kind_shapes() -> None:
    assert detect_kind({"mcpServers": {}}) == ("config", "mcpServers")
    assert detect_kind({"servers": {"a": {"command": "x"}}}) == ("config", "vscode")
    assert detect_kind({"mcp": {"servers": {"a": {"url": "https://x"}}}}) == (
        "config",
        "vscode-settings",
    )
    assert detect_kind({"tools": []}) == ("tools", "tools-object")
    assert detect_kind({"result": {"tools": []}}) == ("tools", "jsonrpc-result")
    assert detect_kind([{"name": "t", "description": "d"}]) == ("tools", "array")
    assert detect_kind({"servers": {"web": "https://not-a-server"}}) is None
    assert detect_kind({"foo": 1}) is None
    assert detect_kind([]) is None
    assert detect_kind("string") is None


def test_references_are_non_literal() -> None:
    for v in (
        "${env:TOKEN}",
        "${input:id}",
        "${workspaceFolder}/x",
        "$HOME",
        "%USERPROFILE%",
        "Bearer ${env:T}",
    ):
        assert not is_literal(v), v
    for v in ("ghp_abc", "/Users/alice", "$", "100$", "a${"):
        assert is_literal(v), v


def test_mcpservers_dialect_normalisation() -> None:
    servers = servers_from(
        {
            "mcpServers": {
                "a b": {
                    "command": "npx",
                    "args": ["-y", "pkg", 7],
                    "env": {"TOKEN": "${env:T}", "N": 1},
                    "autoApprove": ["x", "*"],
                    "unknownKey": True,
                },
                "remote": {
                    "url": "https://h/mcp",
                    "requestInit": {"headers": {"Authorization": "Bearer x"}},
                },
                "sse": {"url": "https://h/sse"},
                "typed": {"type": "sse", "url": "https://h/whatever"},
                "broken": "not a dict",
            }
        }
    )
    by = {s.name: s for s in servers}
    assert set(by) == {"a b", "remote", "sse", "typed"}
    a = by["a b"]
    assert a.json_path == '$.mcpServers["a b"]'
    assert a.transport == "stdio"
    assert a.arg_values == ["-y", "pkg", "7"]
    assert a.args[2].json_path == '$.mcpServers["a b"].args[2]'
    assert a.env["TOKEN"].literal is False
    assert a.env["N"].value == "1"
    assert a.auto_approve == ["x"] and a.auto_approve_all is True
    assert a.unparsed_keys == ["unknownKey"]
    assert by["remote"].transport == "http"
    assert (
        by["remote"]
        .headers["Authorization"]
        .json_path.endswith(".requestInit.headers.Authorization")
    )
    assert by["sse"].transport == "sse"
    assert by["typed"].transport == "sse"


def test_vscode_dialects() -> None:
    vs = servers_from(
        {
            "inputs": [],
            "servers": {"s": {"type": "stdio", "command": "x", "env": {"K": "${input:k}"}}},
        }
    )
    assert vs[0].json_path == "$.servers.s" and vs[0].env["K"].literal is False
    st = servers_from({"mcp": {"servers": {"s": {"url": "http://localhost:1/mcp"}}}})
    assert st[0].json_path == "$.mcp.servers.s" and st[0].transport == "http"


def test_toolset_shapes_and_labels() -> None:
    ts = toolset_from(
        {"server": "weather", "tools": [{"name": "a", "description": "d"}, {"nope": 1}]}
    )
    assert ts.server_label == "weather" and [t.name for t in ts.tools] == ["a"]
    assert ts.tools[0].json_path == "$.tools[0]"
    rpc = toolset_from(
        {
            "result": {
                "tools": [{"name": "b", "inputSchema": {"type": "object"}}],
                "_meta": {"io.modelcontextprotocol/serverInfo": {"name": "svc"}},
            }
        },
        source="x.json",
    )
    assert rpc.server_label == "svc" and rpc.tools[0].json_path == "$.result.tools[0]"
    arr = toolset_from(
        [{"name": "c", "description": "d", "annotations": {"readOnlyHint": True}}],
        source="dir/my-server.json",
    )
    assert arr.server_label == "my-server" and arr.tools[0].annotations == {"readOnlyHint": True}
