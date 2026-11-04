"""End-to-end: scan examples/, compare with expected.json, validate schema, assert no secret leaks."""

from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path

import pytest

from mcp_trustcheck import cli, rules_catalog, scanner
from mcp_trustcheck.report.json import render_json
from mcp_trustcheck.report.terminal import render_terminal

jsonschema = pytest.importorskip("jsonschema")

# Every fabricated credential that appears in examples/. None may appear in any output.
FIXTURE_SECRETS = [
    "ghp_FAKE0000000000000000000000000000FAKE",
    "sk-FAKE000000000000000000000000000000000000FAKE",
    "AKIAIOSFODNN7EXAMPLE",
    "correct-horse-battery-staple-9",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmYWtlIn0.FAKEFAKEFAKEFAKEFAKE",
]


@pytest.fixture(scope="module")
def report(examples_dir: Path):  # type: ignore[no-untyped-def]
    cwd = os.getcwd()
    os.chdir(examples_dir.parent)
    try:
        return scanner.scan(scanner.ScanOptions(inputs=["examples"]))
    finally:
        os.chdir(cwd)


def test_findings_match_oracle(report, expected) -> None:  # type: ignore[no-untyped-def]
    got: dict[str, list[str]] = {k: [] for k in expected}
    for f in report.findings:
        rel = f.affected.file.split("examples/", 1)[1]
        assert rel in expected, f"finding in unexpected file {rel}"
        got[rel].append(f"{f.rule_id}@{f.severity.value}")
    for rel, want in expected.items():
        assert Counter(got[rel]) == Counter(want), (
            f"{rel}: got {sorted(got[rel])}, want {sorted(want)}"
        )


def test_every_rule_has_a_positive_and_negative_fixture(report, expected) -> None:  # type: ignore[no-untyped-def]
    triggered = {f.rule_id for f in report.findings}
    # TOOL-006 needs --baseline; it is covered by test_diff_command_detects_drift.
    assert triggered == set(report.rules_run) - {"TOOL-006"}
    assert any(f.kind.value == "weakness" for f in report.findings)
    negatives = [s.path for s in report.files_scanned if "/negative/" in s.path]
    assert len(negatives) >= 8
    # No negative fixture may produce anything above low/info.
    for rel, rules in expected.items():
        if "/negative/" in rel:
            assert all(r.split("@")[1] in ("low", "info") for r in rules), rel


def test_skipped_files_match_oracle(report, expected_skipped) -> None:  # type: ignore[no-untyped-def]
    got = {s.path.split("examples/", 1)[1]: s.reason for s in report.files_skipped}
    assert got == expected_skipped


def test_json_report_validates_against_schema(report, schema_path: Path) -> None:  # type: ignore[no-untyped-def]
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    data = json.loads(render_json(report))
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(
        data
    )
    assert data["summary"]["total"] == len(data["findings"])
    skipped = {(s["path"], s["reason"]) for s in data["scan"]["files_skipped"]}
    assert ("examples/expected.json", "not_recognised") in skipped


def test_no_fixture_secret_leaks_into_any_output(report) -> None:  # type: ignore[no-untyped-def]
    outputs = (
        render_json(report)
        + render_terminal(report, colour=False)
        + render_terminal(report, colour=True)
    )
    for secret in FIXTURE_SECRETS:
        assert secret not in outputs, f"secret leaked: {secret[:6]}…"


def test_finding_ids_are_stable_across_runs(report, examples_dir: Path) -> None:  # type: ignore[no-untyped-def]
    cwd = os.getcwd()
    os.chdir(examples_dir.parent)
    try:
        again = scanner.scan(scanner.ScanOptions(inputs=["examples"]))
    finally:
        os.chdir(cwd)
    assert sorted(f.id for f in report.findings) == sorted(f.id for f in again.findings)
    assert len({f.id for f in report.findings}) == len(report.findings)


def test_diff_command_detects_drift(examples_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    base = str(examples_dir / "baselines" / "approved.json")
    drifted = str(examples_dir / "baselines" / "drifted.json")
    assert cli.main(["diff", "--baseline", base, drifted, "--format", "json"]) == cli.EXIT_FINDINGS
    data = json.loads(capsys.readouterr().out)
    kinds = {(f["affected"]["tool"], f["severity"]) for f in data["findings"]}
    assert kinds == {("get_weather", "high"), ("run_diagnostics", "medium")}
    assert data["scan"]["rules_run"] == ["TOOL-006"]
    assert cli.main(["diff", "--baseline", base, base, "--format", "json"]) == cli.EXIT_OK


def test_exit_codes_and_filters(examples_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    neg = str(examples_dir / "configs" / "negative")
    pos = str(examples_dir / "configs" / "positive")

    def run(*argv: str) -> tuple[int, str]:
        code = cli.main(list(argv))
        return code, capsys.readouterr().out

    assert run("scan", neg, "--format", "json")[0] == cli.EXIT_OK  # only low/info there
    assert run("scan", neg, "--format", "json", "--fail-on", "info")[0] == cli.EXIT_FINDINGS
    assert run("scan", pos, "--format", "json", "--fail-on", "never")[0] == cli.EXIT_OK

    code, out = run("scan", pos, "--format", "json", "--rules", "CFG-009")
    data = json.loads(out)
    assert code == cli.EXIT_FINDINGS
    assert {f["rule_id"] for f in data["findings"]} == {"CFG-009"} and data["scan"][
        "rules_run"
    ] == ["CFG-009"]

    code, out = run(
        "scan", pos, "--format", "json", "--exclude-rules", "CFG-005,CFG-003", "--fail-on", "never"
    )
    assert "CFG-005" not in json.loads(out)["scan"]["rules_run"]

    assert run("scan", pos, "--rules", "NOPE-001")[0] == cli.EXIT_USAGE
    assert run("scan", str(examples_dir / "does-not-exist"))[0] == cli.EXIT_USAGE

    code, out = run(
        "scan", pos, "--format", "json", "--min-confidence", "high", "--fail-on", "never"
    )
    assert code == cli.EXIT_OK
    assert all(f["confidence"] == "high" for f in json.loads(out)["findings"])


def test_output_guard_and_file_output(examples_dir: Path, tmp_path: Path) -> None:
    pos = str(examples_dir / "configs" / "positive")
    inside = str(examples_dir / "configs" / "positive" / "report.json")
    assert cli.main(["scan", pos, "--format", "json", "--output", inside]) == cli.EXIT_USAGE
    assert not Path(inside).exists()
    out = tmp_path / "report.json"
    assert cli.main(["scan", pos, "--format", "json", "--output", str(out)]) == cli.EXIT_FINDINGS
    assert json.loads(out.read_text(encoding="utf-8"))["summary"]["total"] > 0


def test_rules_command(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["rules"]) == cli.EXIT_OK
    assert "CFG-005" in capsys.readouterr().out
    assert cli.main(["rules", "--explain", "tool-001"]) == cli.EXIT_OK
    assert "Limitations" in capsys.readouterr().out
    assert cli.main(["rules", "--format", "json"]) == cli.EXIT_OK
    assert len(json.loads(capsys.readouterr().out)) == len(rules_catalog.RULES)
    assert cli.main(["rules", "--explain", "CFG-999"]) == cli.EXIT_USAGE
