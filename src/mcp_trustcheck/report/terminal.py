"""Terminal renderer. Colour only on a TTY; honours NO_COLOR and --no-color.

Layout, in order:

1. A one-line header and a severity count.
2. A "Server capabilities" block when package code was read: per server, what the code can do,
   its install hooks and per-tool capability classes; servers whose code was not found say where
   the scan looked.
3. A summary table — one row per finding: number, severity, confidence, rule, title, where.
4. One detail card per finding, in the same order, with a fixed label column and every value
   word-wrapped to the terminal width with a hanging indent. Standards and references are
   rendered as two-column lists (identifier / title, title / URL).

Width is the terminal's when stdout is a TTY (clamped to 72-120 columns), otherwise 100, so
piped or saved output is stable. Label text is fixed; everything that came from a scanned file
passes through `_s` (control-character sanitisation, single line) before it is wrapped.
"""

from __future__ import annotations

import os
import shutil
import sys
import textwrap

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

_FALLBACK_WIDTH = 100
_MIN_WIDTH, _MAX_WIDTH = 72, 120
_INDENT = "  "
_LABEL_W = 11  # "References" + 1
_STD_ID_W = 11  # "MCP01:2025" + 1


def use_colour(no_color_flag: bool) -> bool:
    if no_color_flag or os.environ.get("NO_COLOR"):
        return False
    return bool(getattr(sys.stdout, "isatty", lambda: False)())


def terminal_width() -> int:
    """Terminal width when writing to a TTY; a fixed width otherwise so saved output is stable."""
    if not getattr(sys.stdout, "isatty", lambda: False)():
        return _FALLBACK_WIDTH
    cols = shutil.get_terminal_size(fallback=(_FALLBACK_WIDTH, 24)).columns
    return max(_MIN_WIDTH, min(cols, _MAX_WIDTH))


def _s(text: str | None) -> str:
    """Untrusted text (file names, server/tool names, JSON paths) made terminal-safe and single-line."""
    return sanitize_controls(text or "").replace("\n", "\\n").replace("\r", "\\r")


def _fit(text: str, width: int) -> str:
    """Pad or truncate to exactly `width` characters."""
    if len(text) <= width:
        return text.ljust(width)
    return text[: max(width - 1, 0)] + "…"


def _wrap(text: str, width: int, first: str, rest: str) -> list[str]:
    wrapper = textwrap.TextWrapper(
        width=width,
        initial_indent=first,
        subsequent_indent=rest,
        break_long_words=False,  # keep paths, identifiers and URLs intact
        break_on_hyphens=False,
    )
    return wrapper.wrap(text) or [first.rstrip()]


def _where(f: Finding) -> str:
    if f.affected.tool:
        return f"tool {_s(f.affected.tool)}"
    if f.affected.server:
        return f"server {_s(f.affected.server)}"
    return _s(os.path.basename(f.affected.file))


def render_terminal(report: Report, *, colour: bool, width: int | None = None) -> str:
    width = width or terminal_width()
    value_col = " " * (len(_INDENT) + _LABEL_W)  # plain prefix of every value line

    def c(code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if colour else text

    def sev(s: Severity, text: str) -> str:
        return c(_COLOURS[s], text)

    # -- card primitives. Values are wrapped plain, then the label and colour are applied so that
    #    escape codes never count towards the width.
    def value_lines(text: str, offset: int = 0) -> list[str]:
        prefix = value_col + " " * offset
        return _wrap(text, width, prefix, prefix)

    def emit(label: str, lines: list[str], *, dim: bool = False) -> list[str]:
        """Put `label` (or nothing) in the label column of the first line; optionally dim values."""
        body, rest = lines[0][len(value_col) :], lines[1:]
        if dim:
            body, rest = c(_DIM, body), [c(_DIM, ln) for ln in rest]
        head = _INDENT + (c(_DIM, label.ljust(_LABEL_W)) if label else " " * _LABEL_W)
        return [head + body, *rest]

    def row(label: str, text: str, *, dim: bool = False) -> list[str]:
        return emit(label, value_lines(text), dim=dim)

    def cont(text: str, *, dim: bool = False) -> list[str]:
        return emit("", value_lines(text), dim=dim)

    def pair(label: str, left: str, right: str, left_w: int) -> list[str]:
        """`left` in a bold fixed-width column, `right` wrapped beside it."""
        first, rest = value_col + left.ljust(left_w), value_col + " " * left_w
        lines = _wrap(right, width, first, rest)
        lines[0] = value_col + c(_BOLD, left.ljust(left_w)) + lines[0][len(first) :]
        return emit(label, lines)

    findings = sort_findings(report.findings)
    summary = report.to_dict()["summary"]
    hr = c(_DIM, "─" * width)
    out: list[str] = []

    # ---- header -----------------------------------------------------------------------------
    n_files, n_skipped = len(report.files_scanned), len(report.files_skipped)
    out.append(
        c(_BOLD, f"mcp-trustcheck {report.tool_version}")
        + f"  ·  {n_files} file{'s' if n_files != 1 else ''} scanned  ·  {n_skipped} skipped"
    )
    if report.baseline:
        out.append(c(_DIM, f"baseline: {_s(report.baseline)}"))
    if report.lock:
        out.append(c(_DIM, f"lock: {_s(report.lock)}"))
    if findings:
        by_sev = summary["by_severity"]
        counts = ", ".join(sev(Severity(s), f"{n} {s}") for s, n in by_sev.items() if n)
        out.append(f"{len(findings)} finding{'s' if len(findings) != 1 else ''}: {counts}")
        mcp_top10 = {k: v for k, v in summary["by_standard"].items() if k.startswith("MCP")}
        if mcp_top10:
            out.append(
                c(_DIM, "OWASP MCP Top 10: " + ", ".join(f"{k} x{v}" for k, v in mcp_top10.items()))
            )
    else:
        out.append("No findings.")
    out.append("")

    # ---- server capabilities (from package code) -------------------------------------------
    if report.packages or report.unlocated:
        out.append(
            c(_BOLD, "Server capabilities")
            + c(_DIM, "  (from package code on disk; a static reading, not a verdict)")
        )
        out.append(hr)
        for pkg in report.packages:
            ver = f"@{pkg.version}" if pkg.version else ""
            head = f"{_s(pkg.server)}  {c(_DIM, _s(pkg.name) + ver + '  ' + _s(pkg.root))}"
            out += _wrap(head, width, _INDENT, _INDENT + "  ")
            meta = (
                f"{pkg.files_scanned} file{'s' if pkg.files_scanned != 1 else ''}, {pkg.language}, "
                f"via {pkg.located_by}, attribution: {pkg.attribution}"
            )
            out += [c(_DIM, ln) for ln in _wrap(meta, width, _INDENT + "  ", _INDENT + "    ")]
            out += _wrap(_s(pkg.summary()), width, _INDENT + "  ", _INDENT + "    ")
            if pkg.install_hooks:
                hooks = "; ".join(f"{k}: {v}" for k, v in sorted(pkg.install_hooks.items()))
                out += _wrap(f"install hooks: {_s(hooks)}", width, _INDENT + "  ", _INDENT + "    ")
            attributed = [t for t in pkg.tools.values() if t.handler]
            with_sinks = sorted((t for t in attributed if t.classes), key=lambda t: t.name)
            if with_sinks:
                parts = [f"{_s(t.name)} → {', '.join(sorted(t.classes))}" for t in with_sinks]
                out += _wrap("tools: " + "; ".join(parts), width, _INDENT + "  ", _INDENT + "    ")
            quiet = len(attributed) - len(with_sinks)
            handled = {t.name for t in attributed}
            unattributed = [n for n in pkg.declared_tools if n not in handled]
            tail = []
            if quiet:
                tail.append(f"{quiet} attributed tool{'s' if quiet != 1 else ''} reach no sinks")
            if unattributed:
                n = len(unattributed)
                tail.append(
                    f"{n} declared tool{'s' if n != 1 else ''} not attributed to a handler"
                    + (
                        " ("
                        + ", ".join(_s(x) for x in unattributed[:4])
                        + (", …" if n > 4 else "")
                        + ")"
                    )
                )
            if tail:
                out += [
                    c(_DIM, ln)
                    for ln in _wrap("; ".join(tail), width, _INDENT + "  ", _INDENT + "    ")
                ]
            for note in pkg.notes:
                out += [
                    c(_DIM, ln)
                    for ln in _wrap(f"note: {_s(note)}", width, _INDENT + "  ", _INDENT + "    ")
                ]
        for u in report.unlocated:
            spec = f" {_s(u.spec)}" if u.spec else ""
            text = f"{_s(u.server)}  {u.ecosystem}{spec}: {_s(u.reason)}"
            if u.searched:
                text += " (looked in: " + ", ".join(u.searched) + ")"
            out += [c(_DIM, ln) for ln in _wrap(text, width, _INDENT, _INDENT + "  ")]
        out.append("")

    # ---- summary table ----------------------------------------------------------------------
    if findings:
        wheres = [_where(f) for f in findings]
        num_w = max(2, len(str(len(findings))))
        sev_w, conf_w = 8, 6
        rule_w = max(len(f.rule_id) for f in findings)
        where_w = min(max(len(w) for w in wheres), 30)
        title_w = max(20, width - (num_w + sev_w + conf_w + rule_w + where_w + 10))
        header = (
            f"{'#':>{num_w}}  {'SEVERITY':<{sev_w}}  {'CONF':<{conf_w}}  {'RULE':<{rule_w}}  "
            f"{'FINDING':<{title_w}}  WHERE"
        )
        out.append(c(_BOLD, header))
        out.append(hr)
        for i, (f, where) in enumerate(zip(findings, wheres, strict=True), 1):
            out.append(
                f"{i:>{num_w}}  "
                + sev(f.severity, f"{f.severity.value.upper():<{sev_w}}")
                + f"  {f.confidence.value:<{conf_w}}  {f.rule_id:<{rule_w}}  "
                + _fit(f.title, title_w)
                + "  "
                + c(_DIM, _fit(where, where_w).rstrip())
            )
        out.append("")

    # ---- detail cards -----------------------------------------------------------------------
    for i, f in enumerate(findings, 1):
        out.append(hr)
        out.append(
            c(_BOLD, f"#{i}")
            + "  "
            + sev(f.severity, f"{f.severity.value.upper()} / {f.confidence.value}")
            + f"   {c(_BOLD, f.rule_id)}  {f.title}"
            + c(_DIM, f"   [{f.kind.value}]")
        )
        out.append(hr)
        out += row("File", _s(f.affected.file))
        if f.affected.tool:
            out += row("Tool", _s(f.affected.tool))
        elif f.affected.server:
            out += row("Server", _s(f.affected.server))
        out += row("Path", _s(f.affected.json_path), dim=True)
        out += row("Problem", _s(f.description))
        for j, e in enumerate(f.evidence):
            text = f"{_s(e.json_path)}: {_s(e.snippet)}"
            out += row("Evidence", text) if j == 0 else cont(text)
            if e.note:
                out += cont(f"↳ {_s(e.note)}", dim=True)
        out += row("Fix", f.mitigation)
        for j, s in enumerate(f.standards):
            out += pair(
                "Standards" if j == 0 else "", s.id, f"{s.title}  ({s.framework})", _STD_ID_W
            )
        for j, r in enumerate(f.references):
            out += emit("References" if j == 0 else "", value_lines(r.title))
            out += cont(r.url, dim=True)
        out.append("")

    # ---- trailers ---------------------------------------------------------------------------
    if report.errors:
        out.append(sev(Severity.HIGH, "rule errors (findings from these rules may be incomplete):"))
        for err in report.errors:
            text = f"{err['rule_id']} on {_s(err['file'])}: {_s(err['message'])}"
            out += _wrap(text, width, _INDENT, _INDENT + "  ")
        out.append("")
    if report.files_skipped:
        out.append(c(_DIM, "Skipped:"))
        for sk in report.files_skipped:
            detail = f" ({_s(sk.detail)})" if sk.detail else ""
            text = f"{_s(sk.path)}: {sk.reason}{detail}"
            out += [c(_DIM, ln) for ln in _wrap(text, width, _INDENT, _INDENT + "  ")]
        out.append("")
    footer = (
        "Findings are static indicators; run `mcp-trustcheck rules --explain <ID>` for a rule's "
        "detection logic and limitations. Standards: CWE <https://cwe.mitre.org/>, OWASP MCP Top 10 "
        "2025 <https://owasp.org/www-project-mcp-top-10/>, OWASP Top 10 for LLM Applications 2025 "
        "<https://genai.owasp.org/llm-top-10/>."
    )
    out += [c(_DIM, ln) for ln in _wrap(footer, width, "", "")]
    return "\n".join(out) + "\n"
