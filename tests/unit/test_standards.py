"""Every rule maps to citable standards, and every output surface carries them."""

from __future__ import annotations

import json
import re
from pathlib import Path

from mcp_trustcheck import rules_catalog, scanner
from mcp_trustcheck.cli import main
from mcp_trustcheck.report.json import render_json
from mcp_trustcheck.report.terminal import render_terminal

ROOT = Path(__file__).resolve().parents[2]
ID_RE = re.compile(r"^(CWE-[0-9]+|MCP[0-9]{2}:2025|LLM[0-9]{2}:2025)$")


def test_every_rule_has_a_cwe_and_well_formed_ids() -> None:
    for rid in rules_catalog.all_rule_ids():
        meta = rules_catalog.RULES[rid]
        assert meta.standards, f"{rid} has no standards mapping"
        assert any(s.framework == "CWE" for s in meta.standards), f"{rid} has no CWE"
        for s in meta.standards:
            assert ID_RE.match(s.id), (rid, s.id)
            assert s.title and s.url.startswith("https://"), (rid, s.id)
            if s.framework == "CWE":
                assert s.url == f"https://cwe.mitre.org/data/definitions/{s.id[4:]}.html"
        ids = [s.id for s in meta.standards]
        assert len(ids) == len(set(ids)), f"{rid} lists a standard twice"


def test_standards_titles_are_consistent_across_rules() -> None:
    """The same identifier must never carry two different titles."""
    seen: dict[str, str] = {}
    for meta in rules_catalog.RULES.values():
        for s in meta.standards:
            assert seen.setdefault(s.id, s.title) == s.title, s.id


def test_findings_and_renderers_carry_all_standards_and_references() -> None:
    report = scanner.scan(
        scanner.ScanOptions(inputs=[str(ROOT / "examples" / "configs" / "positive")])
    )
    assert report.findings
    text = render_terminal(report, colour=False)
    data = json.loads(render_json(report))
    assert data["schema_version"] == "1.1"
    for f in report.findings:
        meta = rules_catalog.RULES[f.rule_id]
        assert [s.id for s in f.standards] == [s.id for s in meta.standards]
        for s in f.standards:
            assert s.label in text
        for r in f.references:  # every reference, not only the first
            assert r.url in text
    for jf in data["findings"]:
        assert jf["standards"] and all(ID_RE.match(s["id"]) for s in jf["standards"])


def test_rules_explain_lists_standards(capsys) -> None:  # type: ignore[no-untyped-def]
    assert main(["rules", "--explain", "CFG-005"]) == 0
    out = capsys.readouterr().out
    assert "Standards:" in out and "CWE-798" in out and "MCP01:2025" in out
    assert main(["rules", "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert all(r["standards"] for r in payload)
