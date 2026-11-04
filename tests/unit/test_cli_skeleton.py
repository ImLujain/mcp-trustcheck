from __future__ import annotations

import pytest

from mcp_trustcheck import __version__
from mcp_trustcheck.cli import build_parser


def test_version_matches_package() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["--version"])
    assert exc.value.code == 0
    assert __version__.count(".") == 2


def test_scan_defaults() -> None:
    args = build_parser().parse_args(["scan", "examples/"])
    assert args.format == "terminal"
    assert args.fail_on == "high"
    assert args.min_confidence == "low"
    assert args.follow_symlinks is False


def test_diff_requires_baseline() -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args(["diff", "current.json"])
