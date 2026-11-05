"""Command-line entry point (docs/design.md §4). Argument parsing and exit codes only."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from mcp_trustcheck import __version__, rules_catalog, scanner
from mcp_trustcheck.lock import DEFAULT_LOCK_NAME, write_lock
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

    def add_packages(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--package-path",
            action="append",
            default=[],
            metavar="SERVER=DIR",
            help="read this server's code from DIR instead of searching local launcher caches",
        )
        p.add_argument(
            "--no-packages",
            action="store_true",
            help="do not read any package code (CFG-018/019/020 and TOOL-012 will not run)",
        )

    scan = sub.add_parser("scan", help="scan files or directories")
    scan.add_argument("paths", nargs="+")
    add_output(scan, ["terminal", "json", "both"])
    scan.add_argument("--baseline", metavar="FILE", help="approved tool catalogue for TOOL-006")
    scan.add_argument(
        "--lock",
        metavar="FILE",
        help="lock written by `lock`; enables CFG-020 and per-server TOOL-006",
    )
    scan.add_argument("--fail-on", choices=_SEV_CHOICES, default="high")
    scan.add_argument("--min-confidence", choices=[c.value for c in Confidence], default="low")
    scan.add_argument("--rules", metavar="ID,ID", help="only run these rules")
    scan.add_argument("--exclude-rules", metavar="ID,ID")
    scan.add_argument("--follow-symlinks", action="store_true")
    scan.add_argument(
        "--max-file-size", type=int, default=scanner.DEFAULT_MAX_BYTES, metavar="BYTES"
    )
    scan.add_argument("--max-files", type=int, default=scanner.DEFAULT_MAX_FILES, metavar="N")
    add_packages(scan)
    scan.add_argument("-v", "--verbose", action="store_true")

    lock = sub.add_parser(
        "lock",
        help="record the reviewed state (package version, content digest, capabilities, catalogue)",
    )
    lock.add_argument("paths", nargs="+")
    lock.add_argument(
        "--lock-file",
        metavar="FILE",
        default=DEFAULT_LOCK_NAME,
        help=f"default: {DEFAULT_LOCK_NAME}",
    )
    lock.add_argument("--follow-symlinks", action="store_true")
    add_packages(lock)
    lock.add_argument("-v", "--verbose", action="store_true")

    verify = sub.add_parser("verify", help="report what changed since the lock (CFG-020, TOOL-006)")
    verify.add_argument("paths", nargs="+")
    verify.add_argument(
        "--lock", metavar="FILE", default=DEFAULT_LOCK_NAME, help=f"default: {DEFAULT_LOCK_NAME}"
    )
    add_output(verify, ["terminal", "json", "both"])
    verify.add_argument("--fail-on", choices=_SEV_CHOICES, default="high")
    verify.add_argument("--follow-symlinks", action="store_true")
    add_packages(verify)
    verify.add_argument("-v", "--verbose", action="store_true")

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


def _package_paths(items: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in items:
        name, sep, path = item.partition("=")
        if not sep or not name.strip() or not path.strip():
            raise scanner.ScanError(f"--package-path expects SERVER=DIR, got {item!r}")
        out[name.strip()] = path.strip()
    return out


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


def _print_rule_errors(report: Report) -> None:
    for err in report.errors:
        print(
            f"mcp-trustcheck: rule {err['rule_id']} failed on {err['file']}: {err['message']}",
            file=sys.stderr,
        )


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
        packages=not args.no_packages,
        package_paths=_package_paths(args.package_path),
        lock=args.lock,
    )
    report = scanner.scan(opts)
    _emit_report(report, args)
    _print_rule_errors(report)
    return _exit_for(report, args.fail_on)


def _cmd_diff(args: argparse.Namespace) -> int:
    report = scanner.diff(args.baseline, args.current)
    _emit_report(report, args)
    return _exit_for(report, args.fail_on)


def _cmd_lock(args: argparse.Namespace) -> int:
    opts = scanner.ScanOptions(
        inputs=list(args.paths),
        follow_symlinks=args.follow_symlinks,
        packages=not args.no_packages,
        package_paths=_package_paths(args.package_path),
    )
    report, lock = scanner.lock(opts)
    out = Path(args.lock_file)
    write_lock(out, lock)
    n = len(lock["servers"])
    located = sum(1 for e in lock["servers"].values() if e["package"])
    cats = sum(1 for e in lock["servers"].values() if e["catalogue"])
    print(
        f"lock written to {out}: {n} server{'s' if n != 1 else ''}, "
        f"{located} with package code, {cats} with an approved catalogue."
    )
    for u in report.unlocated:
        print(f"  not located: {u.server} ({u.ecosystem} {u.spec}): {u.reason}", file=sys.stderr)
    _print_rule_errors(report)
    return EXIT_OK


def _cmd_verify(args: argparse.Namespace) -> int:
    opts = scanner.ScanOptions(
        inputs=list(args.paths),
        follow_symlinks=args.follow_symlinks,
        packages=not args.no_packages,
        package_paths=_package_paths(args.package_path),
        lock=args.lock,
    )
    report = scanner.verify(opts)
    _emit_report(report, args)
    _print_rule_errors(report)
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
                "standards": [s.to_dict() for s in m.standards],
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
            print("  Standards:")
            for s in m.standards:
                print(f"    - {s.id}  {s.title}  ({s.framework})\n      {s.url}")
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
        if args.command == "lock":
            return _cmd_lock(args)
        if args.command == "verify":
            return _cmd_verify(args)
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
