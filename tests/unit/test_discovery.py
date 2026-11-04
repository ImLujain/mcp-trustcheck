from __future__ import annotations

import json
import os
from pathlib import Path

from mcp_trustcheck.discovery import discover


def _w(p: Path, content: str | bytes) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        p.write_bytes(content)
    else:
        p.write_text(content, encoding="utf-8")
    return p


def test_discovery_classifies_every_edge_case(tmp_path: Path) -> None:
    root = tmp_path / "root"
    _w(root / "ok.json", json.dumps({"mcpServers": {}}))
    _w(
        root / "nested" / ".cursor" / "mcp.json",
        json.dumps({"mcpServers": {"a": {"command": "x"}}}),
    )
    _w(root / "bad.json", "{not json")
    _w(root / "empty.json", "")
    _w(root / "blank.json", "   \n")
    _w(root / "bin.json", b"\x00\x01\x02")
    _w(root / "big.json", "[" + "1," * 600_000 + "1]")
    _w(root / "deep.json", "[" * 100_000 + "]" * 100_000)
    _w(root / "other.json", json.dumps({"hello": "world"}))
    _w(root / "notes.txt", "ignored")
    _w(root / "node_modules" / "x.json", json.dumps({"mcpServers": {}}))
    outside = _w(tmp_path / "outside.json", json.dumps({"mcpServers": {}}))
    os.symlink(outside, root / "link.json")

    res = discover([str(root)], max_bytes=1_000_000)
    loaded = {p.path.name: p for p in res.loaded}
    skipped = {s.path.rsplit("/", 1)[-1]: s.reason for s in res.skipped}

    assert set(loaded) == {"ok.json", "mcp.json"}
    assert loaded["mcp.json"].dialect == "mcpServers"
    assert skipped == {
        "bad.json": "invalid_json",
        "empty.json": "empty",
        "blank.json": "empty",
        "bin.json": "binary",
        "big.json": "too_large",
        "deep.json": "too_deep",
        "other.json": "not_recognised",
        "link.json": "symlink_outside_root",
    }


def test_symlink_followed_when_allowed(tmp_path: Path) -> None:
    root = tmp_path / "root"
    outside = _w(tmp_path / "outside.json", json.dumps({"mcpServers": {}}))
    root.mkdir()
    os.symlink(outside, root / "link.json")
    assert [s.reason for s in discover([str(root)]).skipped] == ["symlink_outside_root"]
    assert len(discover([str(root)], follow_symlinks=True).loaded) == 1


def test_missing_input_is_skipped_not_raised(tmp_path: Path) -> None:
    res = discover([str(tmp_path / "nope")])
    assert res.loaded == [] and res.skipped[0].reason == "unreadable"


def test_single_file_input_and_dedup(tmp_path: Path) -> None:
    f = _w(tmp_path / "a.json", json.dumps({"tools": []}))
    res = discover([str(f), str(tmp_path)])
    assert len(res.loaded) == 1 and res.loaded[0].kind == "tools"
