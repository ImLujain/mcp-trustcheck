# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow SemVer.

## [0.2.0] — unreleased

The scanner now reads the *code* of each configured server, not only what the server says about
itself. Everything stays offline and read-only: the code is taken from the local launcher cache or
script path the client already uses, never fetched, never executed.

### Added
- **Capability manifests** (`src/mcp_trustcheck/code/`): per server, the package is located on disk
  (`npx`/`bunx`/`pnpm dlx` caches, `uvx`/`pipx` environments, project `node_modules`/virtualenvs, or
  the script path in the config; `--package-path SERVER=DIR` for code you obtained yourself) and
  its Python (`ast`) and JavaScript/TypeScript (import-aware lexical) sources are reduced to sinks in
  eight classes: exec, fs_read, fs_write, fs_delete, network (hosts), env (names), dynamic_code,
  native. Sinks are attributed to tools through the MCP SDK registration idioms and followed through
  the package's own functions. The terminal report opens with one plain-language line per server;
  the JSON report carries the full manifest under `packages` (schema 1.2).
- `TOOL-012` Declared behaviour contradicts the handler's code: `readOnlyHint: true` or read-looking
  tools whose handler reaches exec / write / delete, with file and line.
- `CFG-018` Install-time hook in the launched package; `CFG-019` package can fetch and execute code
  at runtime.
- `lock` and `verify` commands and `CFG-020`: the lock records version, content digest, capability
  classes per package and per tool, install hooks and the approved catalogue; `verify` reports what
  changed. `TOOL-006` now also runs per server against the lock's catalogues.
- `summary.by_standard` in the JSON report and an OWASP MCP Top 10 line in the terminal header.
- Rule count 27 (18 configuration, 9 tool-definition).

### Changed
- Report schema 1.2: `scan.lock`, `summary.by_standard`, top-level `packages`.

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
