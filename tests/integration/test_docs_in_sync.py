"""Generated documentation and the rule catalogue must not drift apart."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

from mcp_trustcheck import rules_catalog, scanner

ROOT = Path(__file__).resolve().parents[2]


def _gen() -> str:
    spec = importlib.util.spec_from_file_location(
        "gen_methodology", ROOT / "scripts" / "gen_methodology.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # dataclasses need the module registered
    spec.loader.exec_module(mod)
    return mod.main()  # type: ignore[no-any-return]


def test_methodology_is_current() -> None:
    committed = (ROOT / "docs" / "methodology.md").read_text(encoding="utf-8")
    assert committed == _gen(), "run: python scripts/gen_methodology.py > docs/methodology.md"


def test_every_rule_is_documented_and_fixtured() -> None:
    doc = (ROOT / "docs" / "methodology.md").read_text(encoding="utf-8")
    expected = json.loads((ROOT / "examples" / "expected.json").read_text(encoding="utf-8"))
    fired = {r.split("@")[0] for k, v in expected.items() if not k.startswith("_") for r in v}
    for rid in rules_catalog.all_rule_ids():
        assert f"### {rid} — " in doc, rid
        assert rid in fired or rid in scanner.LOCK_RULES, (
            f"{rid} has no positive fixture in examples/expected.json"
        )


def test_threat_model_mentions_every_rule() -> None:
    tm = (ROOT / "docs" / "threat-model.md").read_text(encoding="utf-8")
    for rid in rules_catalog.all_rule_ids():
        assert rid in tm, f"{rid} is not in the threat model's proposed-check table"
