"""Command-line entry point (docs/design.md §4). Argument parsing and exit codes only."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from mcp_trustcheck import __version__, rules_catalog, scanner
from mcp_trustcheck.model import Confidence, Report, Severity
from mcp_trustcheck.report.json import render_json
from mcp_trustcheck.report.terminal import render_terminal, use_colour

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_INTERNAL = 3

_SEV_CHOICES = [s.value for s in Severity] + ["never"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-trustcheck",
        description="Read-only static security audit of MCP client configs and tool catalogues.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_output(p: argparse.ArgumentParser, choices: list[str]) -> None:
        p.add_argument("--format", choices=choices, default="terminal")
        p.add_argument("--output", metavar="FILE", help="write the report here instead of stdout")
        p.add_argument("--no-color", action="store_true")

    scan = sub.add_parser("scan", help="scan files or directories")
    scan.add_argument("paths", nargs="+")
    add_output(scan, ["terminal", "json", "both"])
    scan.add_argument("--baseline", metavar="FILE", help="approved tool catalogue for TOOL-006")
    scan.add_argument("--fail-on", choices=_SEV_CHOICES, default="high")
    scan.add_argument("--min-confidence", choices=[c.value for c in Confidence], default="low")
    scan.add_argument("--rules", metavar="ID,ID", help="only run these rules")
    scan.add_argument("--exclude-rules", metavar="ID,ID")
    scan.add_argument("--follow-symlinks", action="store_true")
    scan.add_argument(
        "--max-file-size", type=int, default=scanner.DEFAULT_MAX_BYTES, metavar="BYTES"
    )
    scan.add_argument("--max-files", type=int, default=scanner.DEFAULT_MAX_FILES, metavar="N")
    scan.add_argument("-v", "--verbose", action="store_true")

    diff = sub.add_parser("diff", help="compare a tool catalogue against an approved baseline")
    diff.add_argument("--baseline", required=True, metavar="FILE")
    diff.add_argument("current")
    add_output(diff, ["terminal", "json", "both"])
    diff.add_argument("--fail-on", choices=_SEV_CHOICES, default="high")
    diff.add_argument("-v", "--verbose", action="store_true")

    rules = sub.add_parser("rules", help="list or explain the implemented checks")
    rules.add_argument("--explain", metavar="ID")
    rules.add_argument("--format", choices=["terminal", "json"], default="terminal")
    return parser


def _split_ids(s: str | None) -> set[str]:
    return {x.strip().upper() for x in s.split(",") if x.strip()} if s else set()


def _emit_report(report: Report, args: argparse.Namespace) -> None:
    fmt = args.format
    out_path = Path(args.output) if args.output else None
    if out_path is not None:
        resolved = out_path.resolve()
        for raw in getattr(args, "paths", [getattr(args, "current", "")]):
            try:
                root = Path(raw).resolve(strict=True)
            except OSError:
                continue
            if root.is_dir() and (resolved == root or root in resolved.parents):
                raise scanner.ScanError(f"--output must not be inside a scanned directory ({raw})")
    colour = use_colour(args.no_color) and out_path is None
    if fmt in ("terminal", "both"):
        text = render_terminal(report, colour=colour)
        if out_path is not None and fmt == "terminal":
            out_path.write_text(text, encoding="utf-8")
        else:
            sys.stdout.write(text)
    if fmt in ("json", "both"):
        text = render_json(report)
        if out_path is not None:
            out_path.write_text(text, encoding="utf-8")
            if fmt == "both":
                sys.stdout.write(f"JSON report written to {out_path}\n")
        else:
            sys.stdout.write(text)


def _exit_for(report: Report, fail_on: str) -> int:
    if fail_on == "never":
        return EXIT_OK
    threshold = Severity(fail_on).rank
    return EXIT_FINDINGS if any(f.severity.rank >= threshold for f in report.findings) else EXIT_OK


def _cmd_scan(args: argparse.Namespace) -> int:
    opts = scanner.ScanOptions(
        inputs=list(args.paths),
        baseline=args.baseline,
        rules=_split_ids(args.rules) or None,
        exclude_rules=_split_ids(args.exclude_rules),
        min_confidence=Confidence(args.min_confidence),
        follow_symlinks=args.follow_symlinks,
        max_bytes=args.max_file_size,
        max_files=args.max_files,
    )
    report = scanner.scan(opts)
    _emit_report(report, args)
    for err in report.errors:
        print(
            f"mcp-trustcheck: rule {err['rule_id']} failed on {err['file']}: {err['message']}",
            file=sys.stderr,
        )
    return _exit_for(report, args.fail_on)


def _cmd_diff(args: argparse.Namespace) -> int:
    report = scanner.diff(args.baseline, args.current)
    _emit_report(report, args)
    return _exit_for(report, args.fail_on)


def _cmd_rules(args: argparse.Namespace) -> int:
    ids = [args.explain.upper()] if args.explain else rules_catalog.all_rule_ids()
    metas = []
    for rid in ids:
        if rid not in rules_catalog.RULES:
            print(f"unknown rule: {rid}", file=sys.stderr)
            return EXIT_USAGE
        metas.append(rules_catalog.RULES[rid])
    if args.format == "json":
        payload = [
            {
                "id": m.id,
                "title": m.title,
                "threat": m.threat,
                "property": m.property,
                "kind": m.kind.value,
                "default_severity": m.severity.value,
                "default_confidence": m.confidence.value,
                "detection": m.detection,
                "impact": m.impact,
                "mitigation": m.mitigation,
                "limitations": m.limitations,
                "references": [r.to_dict() for r in m.references],
                "spec_note": m.spec_note,
            }
            for m in metas
        ]
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return EXIT_OK
    for m in metas:
        if args.explain:
            print(f"{m.id}  {m.title}\n")
            for label, text in (
                ("Threat", m.threat),
                ("Property", m.property),
                ("Kind", m.kind.value),
                ("Default severity", m.severity.value),
                ("Default confidence", m.confidence.value),
                ("Detection", m.detection),
                ("Impact", m.impact),
                ("Mitigation", m.mitigation),
                ("Limitations", m.limitations),
                ("Spec note", m.spec_note or "—"),
            ):
                print(f"  {label}:\n    {text}")
            print("  References:")
            for r in m.references:
                print(f"    - {r.title}\n      {r.url}")
        else:
            print(f"{m.id:<9} {m.severity.value:<8} {m.kind.value:<9} {m.title}")
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            return _cmd_scan(args)
        if args.command == "diff":
            return _cmd_diff(args)
        return _cmd_rules(args)
    except scanner.ScanError as exc:
        print(f"mcp-trustcheck: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except Exception as exc:
        if getattr(args, "verbose", False):
            raise
        print(
            f"mcp-trustcheck: internal error: {type(exc).__name__}: {exc} (re-run with -v)",
            file=sys.stderr,
        )
        return EXIT_INTERNAL


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
