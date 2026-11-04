"""Terminal renderer. Colour only on a TTY; honours NO_COLOR and --no-color."""

from __future__ import annotations

import os
import sys
from collections import defaultdict

from mcp_trustcheck.model import Report, Severity, sort_findings
from mcp_trustcheck.redaction import sanitize_controls

_COLOURS = {
    Severity.CRITICAL: "\x1b[1;35m",
    Severity.HIGH: "\x1b[1;31m",
    Severity.MEDIUM: "\x1b[33m",
    Severity.LOW: "\x1b[36m",
    Severity.INFO: "\x1b[2m",
}
_RESET = "\x1b[0m"
_BOLD = "\x1b[1m"
_DIM = "\x1b[2m"


def use_colour(no_color_flag: bool) -> bool:
    if no_color_flag or os.environ.get("NO_COLOR"):
        return False
    return bool(getattr(sys.stdout, "isatty", lambda: False)())


def _s(text: str | None) -> str:
    """Untrusted text (file names, server/tool names, JSON paths) made terminal-safe and single-line."""
    return sanitize_controls(text or "").replace("\n", "\\n").replace("\r", "\\r")


def render_terminal(report: Report, *, colour: bool) -> str:
    def c(code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if colour else text

    findings = sort_findings(report.findings)
    d = report.to_dict()
    sev_counts = d["summary"]["by_severity"]
    lines: list[str] = []
    counts = ", ".join(f"{n} {s}" for s, n in sev_counts.items() if n)
    lines.append(
        c(_BOLD, f"mcp-trustcheck {report.tool_version}")
        + f" — {len(report.files_scanned)} file(s) scanned, {len(report.files_skipped)} skipped — "
        + (f"{len(findings)} finding(s): {counts}" if findings else "no findings")
    )
    if report.baseline:
        lines.append(c(_DIM, f"baseline: {_s(report.baseline)}"))
    lines.append("")

    by_file: dict[str, list] = defaultdict(list)  # type: ignore[type-arg]
    for f in findings:
        by_file[f.affected.file].append(f)

    for file, items in by_file.items():
        lines.append(c(_BOLD, _s(file)))
        for f in items:
            target = _s(f.affected.tool or f.affected.server or "")
            head = f"[{f.severity.value.upper()} / {f.confidence.value}] {f.rule_id} {f.title}"
            lines.append("  " + c(_COLOURS[f.severity], head) + c(_DIM, f"  ({f.kind.value})"))
            if target:
                lines.append(
                    f"    {'tool' if f.affected.tool else 'server'}: {target}   {c(_DIM, _s(f.affected.json_path))}"
                )
            lines.append(f"    {_s(f.description)}")
            for e in f.evidence:
                note = f"  — {_s(e.note)}" if e.note else ""
                lines.append(f"    {c(_DIM, 'evidence')}  {_s(e.json_path)}: {_s(e.snippet)}{note}")
            lines.append(f"    {c(_DIM, 'fix')}       {f.mitigation}")
            lines.append(
                f"    {c(_DIM, 'ref')}       {f.references[0].title} <{f.references[0].url}>"
            )
            lines.append("")

    if report.errors:
        lines.append(
            c(_COLOURS[Severity.HIGH], "rule errors (findings from these rules may be incomplete):")
        )
        for err in report.errors:
            lines.append(f"  {err['rule_id']} on {_s(err['file'])}: {_s(err['message'])}")
        lines.append("")
    if report.files_skipped:
        lines.append(c(_DIM, "skipped:"))
        for s in report.files_skipped:
            detail = f" ({_s(s.detail)})" if s.detail else ""
            lines.append(c(_DIM, f"  {_s(s.path)}: {s.reason}{detail}"))
        lines.append("")
    lines.append(
        c(
            _DIM,
            "Findings are static indicators; see `mcp-trustcheck rules --explain <ID>` for each rule's limitations.",
        )
    )
    return "\n".join(lines) + "\n"
