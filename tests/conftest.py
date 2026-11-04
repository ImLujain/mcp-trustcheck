from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from mcp_trustcheck import checks
from mcp_trustcheck.loaders import detect_kind
from mcp_trustcheck.loaders.config import load_servers
from mcp_trustcheck.loaders.tools import load_toolset
from mcp_trustcheck.model import Finding, ServerConfig, ToolSet

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = REPO_ROOT / "examples"
SCHEMA = REPO_ROOT / "docs" / "schema" / "report.schema.json"


@pytest.fixture(scope="session")
def examples_dir() -> Path:
    return EXAMPLES


@pytest.fixture(scope="session")
def schema_path() -> Path:
    return SCHEMA


@pytest.fixture(scope="session")
def expected() -> dict[str, list[str]]:
    data = json.loads((EXAMPLES / "expected.json").read_text(encoding="utf-8"))
    return {k: v for k, v in data.items() if not k.startswith("_")}


@pytest.fixture(scope="session")
def expected_skipped() -> dict[str, str]:
    data = json.loads((EXAMPLES / "expected.json").read_text(encoding="utf-8"))
    return dict(data["_skipped"])


def servers_from(obj: dict[str, Any], source: str = "test.json") -> list[ServerConfig]:
    kind = detect_kind(obj)
    assert kind is not None and kind[0] == "config", "fixture is not a config"
    return load_servers(obj, kind[1], source)


def toolset_from(obj: Any, source: str = "tools.json") -> ToolSet:
    kind = detect_kind(obj)
    assert kind is not None and kind[0] == "tools", "fixture is not a tool catalogue"
    return load_toolset(obj, kind[1], source)


def run_rule(rule_id: str, obj: Any, *, baseline: Any = None) -> list[Finding]:
    """Run a single rule over an in-memory fixture and return its findings."""
    ctx = checks.Context()
    kind = detect_kind(obj)
    assert kind is not None
    if kind[0] == "config":
        ctx.servers = servers_from(obj)
        from mcp_trustcheck.checks.config.secrets import collect_sensitive_values

        collect_sensitive_values(ctx.servers, ctx.redactor)
    else:
        ctx.toolsets = [toolset_from(obj)]
    if baseline is not None:
        ctx.baseline = toolset_from(baseline, "baseline.json")
        ctx.baseline_path = "baseline.json"
    return checks.run_checks(ctx, [rule_id])
