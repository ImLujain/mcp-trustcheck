"""Terminal renderer. Colour only on a TTY; honours NO_COLOR and --no-color.

Layout (one block per finding, grouped by file, ordered by severity then confidence):

    #3  [HIGH / medium]  CFG-005  Hardcoded credential in configuration   (weakness)
        where      server 'elementor-staging'  $.mcpServers["elementor-staging"].headers.Authorization
        what       Server 'elementor-staging' stores what appears to be a credential in plaintext ...
        evidence   $.mcpServers[...].headers.Authorization: bHVq…[redacted 44 chars]  — detector: ...
        fix        Reference the secret instead of embedding it ...
        standards  CWE-798 Use of Hard-coded Credentials · CWE-312 ... · MCP01:2025 ... · LLM02:2025 ...
        refs       OWASP Secrets Management Cheat Sheet <https://...>
                   MCP Security Best Practices — Token Passthrough <https://...>

Every reference and every standard a rule carries is printed, so a finding can be cited in a
report without consulting the catalogue. Label text is fixed; everything after a label that came
from a scanned file passes through `_s` (control-character sanitisation, single line).
"""

from __future__ import annotations

import os
import sys
from collections import defaultdict

from mcp_trustcheck.model import Finding, Report, Severity, sort_findings
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
_UNDERLINE = "\x1b[4m"

_LABEL_W = 10  # width of the label column ("standards" is the longest label)
_INDENT = "    "  # body indent; also the width of the "#n" marker so rows align under the head


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

    def row(label: str, text: str) -> str:
        return f"{_INDENT}{c(_DIM, label.ljust(_LABEL_W))} {text}"

    def cont(text: str) -> str:
        """Continuation line under a multi-line row (same column as the row text)."""
        return f"{_INDENT}{' ' * _LABEL_W} {text}"

    findings = sort_findings(report.findings)
    summary = report.to_dict()["summary"]
    lines: list[str] = []

    # ---- header -----------------------------------------------------------------------------
    lines.append(
        c(_BOLD, f"mcp-trustcheck {report.tool_version}")
        + f" — {len(report.files_scanned)} file(s) scanned, {len(report.files_skipped)} skipped"
    )
    if report.baseline:
        lines.append(c(_DIM, f"baseline: {_s(report.baseline)}"))
    if findings:
        sev = summary["by_severity"]
        kind = summary["by_kind"]
        lines.append(
            f"{len(findings)} finding(s)  "
            + "  ".join(c(_COLOURS[Severity(s)], f"{n} {s}") for s, n in sev.items() if n)
            + c(_DIM, f"   ({', '.join(f'{n} {k}' for k, n in kind.items() if n)})")
        )
    else:
        lines.append("no findings")
    lines.append("")

    # ---- findings, grouped by file ----------------------------------------------------------
    by_file: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_file[f.affected.file].append(f)

    n = 0
    for file, items in by_file.items():
        lines.append(c(_BOLD + _UNDERLINE, _s(file)))
        lines.append("")
        for f in items:
            n += 1
            head = f"[{f.severity.value.upper()} / {f.confidence.value}]  {f.rule_id}  {f.title}"
            marker = f"#{n}".ljust(len(_INDENT))
            lines.append(
                c(_BOLD, marker) + c(_COLOURS[f.severity], head) + c(_DIM, f"   ({f.kind.value})")
            )
            if f.affected.tool:
                where = f"tool '{_s(f.affected.tool)}'"
            elif f.affected.server:
                where = f"server '{_s(f.affected.server)}'"
            else:
                where = "file"
            lines.append(row("where", f"{where}  {c(_DIM, _s(f.affected.json_path))}"))
            lines.append(row("what", _s(f.description)))
            for i, e in enumerate(f.evidence):
                note = c(_DIM, f"  — {_s(e.note)}") if e.note else ""
                text = f"{_s(e.json_path)}: {_s(e.snippet)}{note}"
                lines.append(row("evidence", text) if i == 0 else cont(text))
            lines.append(row("fix", f.mitigation))
            for i, s in enumerate(f.standards):
                text = f"{s.label} {c(_DIM, f'({s.framework})')}"
                lines.append(row("standards", text) if i == 0 else cont(text))
            for i, r in enumerate(f.references):
                text = f"{r.title} {c(_DIM, f'<{r.url}>')}"
                lines.append(row("refs", text) if i == 0 else cont(text))
            lines.append("")

    # ---- trailers ---------------------------------------------------------------------------
    if report.errors:
        lines.append(
            c(_COLOURS[Severity.HIGH], "rule errors (findings from these rules may be incomplete):")
        )
        for err in report.errors:
            lines.append(f"  {err['rule_id']} on {_s(err['file'])}: {_s(err['message'])}")
        lines.append("")
    if report.files_skipped:
        lines.append(c(_DIM, "skipped:"))
        for sk in report.files_skipped:
            detail = f" ({_s(sk.detail)})" if sk.detail else ""
            lines.append(c(_DIM, f"  {_s(sk.path)}: {sk.reason}{detail}"))
        lines.append("")
    if findings:
        lines.append(
            c(
                _DIM,
                "Standards: CWE <https://cwe.mitre.org/>, OWASP MCP Top 10 2025 "
                "<https://owasp.org/www-project-mcp-top-10/>, OWASP Top 10 for LLM Applications 2025 "
                "<https://genai.owasp.org/llm-top-10/>.",
            )
        )
    lines.append(
        c(
            _DIM,
            "Findings are static indicators; see `mcp-trustcheck rules --explain <ID>` for each rule's limitations.",
        )
    )
    return "\n".join(lines) + "\n"
