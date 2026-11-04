# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow SemVer.

## [0.1.0] — unreleased

Initial MVP.

### Added
- Standards mapping on every rule: CWE identifiers plus OWASP MCP Top 10 (2025) and OWASP Top 10
  for LLM Applications (2025) entries. Carried on each finding (`standards[]`, report schema 1.1),
  in `rules --explain` / `rules --format json`, and in `docs/methodology.md`.
- Terminal report reorganised: a summary table, then one detail card per finding with a fixed label
  column and text wrapped to the terminal width; every reference is printed, not just the first.
- `not_recognised` skips now say what structure was looked for.
- `scan`, `diff` and `rules` commands; terminal and JSON output; deterministic exit codes.
- 23 checks (15 configuration, 8 tool-definition) with separate severity and confidence, each mapped
  to a security property or stated hypothesis (`docs/methodology.md`).
- Config dialects: the `mcpServers` family and VS Code `servers`/`inputs`; tool catalogues as
  `tools/list` results, `{tools:[…]}` objects or bare arrays.
- Baseline drift detection (offline rug-pull detection) via canonical SHA-256 per tool.
- Scan-wide secret redaction applied at finding construction.
- 34 synthetic fixtures with a hand-reviewed oracle, 103 tests, strict typing, zero runtime
  dependencies.

### Security (of the tool itself)
- Control-character sanitisation in all report output after the Phase 5 review found that server and
  tool names could inject ANSI/OSC sequences into the terminal report.
- Per-rule error isolation so one failing rule cannot suppress the findings of the others.
- Explicit JSON nesting-depth limit, regular-file guard, file-count cap, narrowed symlink TOCTOU.

### Changed
- Renamed from the working name `mcp-audit` to `mcp-trustcheck` to avoid colliding with the command
  installed by the existing `mcp-audit-scanner` project.
