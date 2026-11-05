# mcp-trustcheck — Phase 2 Design

**Status:** Draft, 2026-11-02
**Depends on:** `docs/threat-model.md` (Phase 1)

This document fixes the MVP scope, the data model, the findings schema, the CLI contract, the repository architecture and the security requirements the tool imposes on itself. Phase 3 implements exactly this; anything not listed here is future work.

---

## 1. MVP definition

### 1.1 In scope

| Capability | Input | Checks (threat-model §6) |
|---|---|---|
| Configuration analysis | MCP client config files (JSON) | CFG-001 … CFG-014 |
| Tool / trust-boundary analysis | Tool catalogue snapshots (JSON) | TOOL-001 … TOOL-005, TOOL-007, TOOL-008, TOOL-009, CFG-015 |
| Baseline drift | Two tool catalogue snapshots | TOOL-006 |
| Reporting | — | Terminal (human) and JSON (machine), both redacted |

### 1.2 Explicitly out of scope for the MVP

- Connecting to any server, spawning any command, or reading server source code (TOOL-010, TOOL-011, CFG-017).
- YAML/TOML configs, server-side framework settings, Docker Compose files (CFG-016 partially).
- Any remediation that writes to a scanned file.
- Any network access.

### 1.3 Definition of done (from the brief, made testable)

1. `mcp-trustcheck scan examples/` runs offline on a clean checkout and exits 0/1/2 deterministically.
2. Every MVP check has ≥1 positive fixture that triggers it and ≥1 negative fixture that does not.
3. `pytest` passes; the JSON report validates against `docs/schema/report.schema.json`.
4. No secret value from any fixture appears unredacted in terminal or JSON output (asserted by test).
5. Malformed, empty, oversized, binary, and symlinked inputs produce a `skipped` entry, never a crash.

---

## 2. Inputs and dialects

### 2.1 Discovery

`scan` accepts files and/or directories. Directories are walked (not following symlinks by default) and only these are considered:

| Pattern | Treated as |
|---|---|
| `claude_desktop_config.json`, `.mcp.json`, `mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `settings.json` containing an `mcp`/`mcpServers` key, `*.mcp.json` | Client config |
| `*.tools.json`, `tools.json`, `tools-list.json`, any JSON whose top level is a Tool array or a `tools/list` result | Tool catalogue |
| Anything else | Ignored (listed in `skipped` with reason `not_recognised`) |

Kind detection is **structural** (shape of the parsed JSON), with filename only as a hint. A file matching neither shape is skipped, never guessed.

### 2.2 Config dialects normalised in the MVP

| Dialect | Root key | Server shape (subset understood) |
|---|---|---|
| `mcpServers` (Claude Desktop, Claude Code `.mcp.json`, Cursor, Windsurf, many others) | `mcpServers: { <name>: {...} }` | `command`, `args[]`, `env{}`, `url`, `headers{}`, `type` (`stdio`/`http`/`sse`), `cwd`, plus client-specific: `autoApprove[]`, `alwaysAllow[]`, `trust`, `disabled` |
| VS Code | `servers: { <name>: {...} }` + `inputs: [...]` | same keys; `${input:ID}`, `${env:VAR}`, `${workspaceFolder}` references recognised as **non-literal** |

Normalised model (`ServerConfig`):

```
name, source_file, json_path,
transport: "stdio" | "http" | "sse" | "unknown",
command: str | None, args: list[str], env: dict[str, ConfigValue],
url: str | None, headers: dict[str, ConfigValue],
approval: {auto_approve: list[str] | "*" | None, trust: bool | None},
raw: dict  # unknown keys preserved for evidence; reported as "unparsed"
```

`ConfigValue` carries `value: str` and `literal: bool`. A value is non-literal if it is a `${…}` reference. Secret checks (CFG-005) and injection-env checks (CFG-008) only fire on literal values.

### 2.3 Tool catalogue shapes

Accepted:
1. A JSON-RPC `tools/list` response: `{ "result": { "tools": [...] } }` (either revision; `resultType`, `ttlMs`, `cacheScope`, `nextCursor` ignored but preserved).
2. A bare `{ "tools": [...] }` object.
3. A bare array of Tool objects.

Normalised `ToolDefinition`: `name, title, description, input_schema, output_schema, annotations{readOnlyHint,destructiveHint,idempotentHint,openWorldHint,title}, source_file, index, raw`. An optional top-level `"server"` string (or `_meta.io.modelcontextprotocol/serverInfo.name`) is used for cross-server checks when present; otherwise the file stem is the server label.

### 2.4 Baseline

`mcp-trustcheck diff --baseline <approved.json> <current.json>` runs TOOL-006 only. Canonical form of a tool = JSON of `{name, description, inputSchema, outputSchema, annotations, title}` with sorted keys, no whitespace, NFC-normalised strings → SHA-256. `scan` also accepts `--baseline` to run TOOL-006 against every tool catalogue it finds.

---

## 3. Data model

```
Severity   = critical | high | medium | low | info
Confidence = high | medium | low
Kind       = weakness   # a documented security property is not met
           | indicator  # needs human review; not asserted as a flaw
           | info       # surface enumeration, no weakness asserted

Finding:
  id            str   # "<RULE>-<8 hex>" ; hex = sha256(rule, file, json_path, evidence key)[:8] — stable across runs
  rule_id       str   # e.g. CFG-003
  title         str
  description   str   # what was observed, in plain language
  kind          Kind
  severity      Severity
  confidence    Confidence
  affected      { file, server?, tool?, json_path }
  evidence      [ { json_path, snippet, note? } ]   # snippet is ALWAYS redacted
  impact        str
  mitigation    str
  references    [ { title, url } ]
  standards     [ { framework, id, title, url } ]   CWE / OWASP MCP Top 10 / OWASP LLM Top 10
  limitations   str   # the FP/FN statement for this rule
  spec_note     str?  # which protocol revision the rationale depends on

Report:
  schema_version  "1.1"
  tool            { name, version }
  generated_at    ISO-8601 UTC
  scan            { inputs[], files_scanned[], files_skipped[{path, reason}], rules_run[], baseline? }
  summary         { by_severity{}, by_confidence{}, by_kind{}, total }
  findings        [ Finding ]   # sorted: severity desc, confidence desc, file, json_path
```

There is deliberately **no aggregate score**. Severity and confidence are determined per rule by the tables in `threat-model.md §5–6`; each rule class documents its rationale in its module docstring and that text is surfaced by `mcp-trustcheck rules --explain <ID>`.

---

## 4. CLI contract

```
mcp-trustcheck scan  <path>... [--format terminal|json|both] [--output FILE]
                          [--baseline FILE] [--fail-on critical|high|medium|low|info|never]
                          [--min-confidence high|medium|low] [--rules ID,ID] [--exclude-rules ID,ID]
                          [--follow-symlinks] [--max-file-size BYTES] [--no-color] [-v]
mcp-trustcheck diff  --baseline FILE <current.json> [--format ...] [--output FILE]
mcp-trustcheck rules [--explain ID] [--format terminal|json]
mcp-trustcheck --version
```

Exit codes: `0` no finding at or above `--fail-on` (default `high`); `1` at least one such finding; `2` usage error or no scannable input; `3` internal error (traceback only with `-v`). Skipped files never change the exit code.

Terminal output: a summary table (number, severity, confidence, rule, title, where) followed by one detail card per finding — `File` / `Server` or `Tool` / `Path` / `Problem` / `Evidence` / `Fix` / `Standards` / `References` rows in a fixed label column, every value word-wrapped to the terminal width (TTY width clamped to 72–120; fixed 100 when piped). Every reference and standard the rule carries is printed. Colour only when stdout is a TTY and `--no-color` is absent; `NO_COLOR` env honoured. `--format json` writes the Report object and nothing else to stdout (or `--output`).

---

## 5. Architecture

```
src/mcp_trustcheck/
  __init__.py          version
  cli.py               argparse only; no logic
  model.py             dataclasses in §3 + enums
  discovery.py         path validation, walking, size/type gating → list[InputFile]
  loaders/
    __init__.py        detect_kind(json) → "config" | "tools" | None
    config.py          dialect parsers → list[ServerConfig]
    tools.py           → list[ToolDefinition]
    refs.py            ${…} reference detection (literal vs non-literal)
  checks/
    __init__.py        Check protocol, registry, run_all()
    _util.py           shared helpers (loopback detection, shell detection, package-spec parsing)
    config/            one module per CFG rule family (exec.py, secrets.py, filesystem.py, container.py, transport.py, approval.py, duplicates.py)
    tools/             one module per TOOL rule family (instructions.py, hidden.py, crossref.py, annotations.py, schema.py, drift.py, collisions.py, ingress.py, headers.py)
  redaction.py         redact(value) → "<prefix>…[redacted N chars]" ; applied at Finding construction, not at output
  report/
    __init__.py
    terminal.py
    json.py
  rules_catalog.py     static metadata for every rule (title, severity default, references, limitations) — single source of truth for docs and `rules` command
tests/
  unit/                one test module per check module; loaders; redaction; discovery
  integration/         scan examples/ end-to-end; schema validation; exit codes; secret-leak assertion
  conftest.py
examples/
  configs/positive/    one file per CFG rule (e.g. cfg-003-shell-wrapper.json)
  configs/negative/    benign equivalents (e.g. cfg-003-benign-args-with-pipe-char.json)
  tools/positive/      poisoned / mismatched catalogues
  tools/negative/      clean catalogues
  baselines/           approved.json + drifted.json for TOOL-006
  (sample reports live in docs/samples/ so they are not themselves scanned)
docs/
  threat-model.md, design.md, methodology.md (per-check write-ups, Phase 5), schema/report.schema.json
  samples/   scan-examples.{json,txt}, diff-baseline.txt, rules.txt — regenerated from examples/ as evidence
.github/workflows/ci.yml   ruff + mypy + pytest on 3.10–3.13
```

Design rules:
- A check is a pure function `(ServerConfig | ToolDefinition | ToolSet, Context) -> list[Finding]`. No I/O inside checks.
- Checks never see raw secret strings in evidence output: `Finding` construction calls `redact()` on every snippet.
- `rules_catalog.py` is the only place severity defaults, references and limitation text live; checks import from it. This keeps README tables, `rules --explain`, and findings in sync.
- Dependencies: **runtime none beyond the standard library**. Dev: `pytest`, `jsonschema`, `ruff`, `mypy`. Python ≥ 3.10.

---

## 6. Security requirements on the tool itself

| Requirement (brief §4) | Mechanism |
|---|---|
| Never execute scanned commands | No `subprocess`, `os.system`, `eval`, `exec` anywhere in `src/`; enforced by a test that greps the package. |
| Never connect to discovered servers | No `socket`, `urllib`, `http.client`, `requests` imports in `src/`; same test. |
| Never transmit data | Same as above. |
| Never print secrets | `redact()` applied at Finding construction; integration test scans all output for every fixture secret. |
| Path validation | Inputs resolved with `Path.resolve(strict=True)`; files outside the user-supplied roots (via symlink) skipped unless `--follow-symlinks`; `..` segments after resolution rejected. |
| Read-only | Files opened `rb` only; no writes except `--output`, which must not point inside a scanned root (checked). |
| Safe failure | Every loader wrapped; failures become `files_skipped[{reason}]`; `json.load` with size cap (default 2 MiB) and depth guard. |
| No paid APIs / AI services | stdlib only. |

---

## 7. Test strategy

- **Unit:** each rule module → parametrised positive/negative cases drawn directly from `examples/`, plus edge cases (missing fields, wrong types, `${env:}` references, empty arrays).
- **Integration:** `scan examples/` produces a report that (a) validates against the schema, (b) contains exactly the expected rule IDs per positive fixture and none for negative fixtures (`examples/expected.json` maps fixture → rule IDs), (c) leaks no fixture secret, (d) yields documented exit codes.
- **Robustness:** malformed JSON, empty file, 10 MiB file, binary file, deeply nested JSON, symlink out of root, directory with no recognisable files.
- **Self-security:** static assertion that forbidden modules are not imported in `src/`.

---

## 8. Open items

1. **License** — Apache-2.0 (confirmed in Phase 6).
2. **Distribution name** — renamed from the working name `mcp-audit` to `mcp-trustcheck` in Phase 6 after discovering the `mcp-audit` command is already installed by `mcp-audit-scanner`.
3. **Windows paths** in CFG-006 (`C:\`, `%USERPROFILE%`) — handled as string patterns, not resolved; noted as limitation.

---

## 8. Package code analysis (0.2.0)

### 8.1 Why

Sections 1–7 judge a server by what it *says*: the launch line and the tool catalogue. Both are
attacker-authored. 0.2.0 adds what the server *is*: the code the launcher would run, which the
client has already installed on disk. The guarantees of §6 are unchanged — nothing is executed,
nothing is fetched, nothing is written — because the code is only ever *read* from where the
client's own launcher put it.

### 8.2 Locating code (`code/locate.py`)

| Launch shape | Where the code is read from |
|---|---|
| `npx` / `bunx` / `pnpm dlx` / `yarn dlx` `<pkg>` | `~/.npm/_npx/*/node_modules/<pkg>`, `~/.bun/install/cache/<pkg>@<ver>`, pnpm `dlx` cache, project `node_modules`, global `node_modules` (`npm_config_prefix`, nvm, Homebrew, `NODE_PATH`) |
| `uvx` / `pipx run` `<dist>` | uv `archive-v*` cache and tool dirs, pipx venvs, `$VIRTUAL_ENV`, `.venv` near the config — matched by `<dist>-<ver>.dist-info`, members from `top_level.txt` / `RECORD` |
| `node x.js`, `python x.py`, `uv run x.py`, `command: ./x.py` | the script, resolved against the config's directory then the CWD; package root = the nearest ancestor (≤ 2 levels) with `package.json` / `pyproject.toml` / `setup.py` |
| `--package-path SERVER=DIR` | exactly that directory or file |
| `docker run …`, remote `url`, `${…}` package names | not located; the report says why |

An exact version in the config is preferred; otherwise the newest cache entry is used and the
mismatch is stated in `located_by`.

### 8.3 Capability manifest (`code/model.py`, `code/extract.py`)

A manifest is a list of *sinks* — `(class, file, line, callee, detail)` — in eight classes:
`exec`, `fs_read`, `fs_write`, `fs_delete`, `network` (detail: host), `env` (detail: variable
name), `dynamic_code`, `native`. Plus: install hooks (`package.json` `preinstall`/`install`/
`postinstall`/`prepare`, `setup.py` `cmdclass`), a content digest (SHA-256 over every file read),
declared tool names and per-tool capabilities.

- **Python** (`code/python.py`): `ast`. Callees are resolved through the module's imports, so
  `import subprocess as sp; sp.run(…)` is `subprocess.run`. Handlers: `@x.tool(name=…)`,
  `x.add_tool(fn)`, `@x.call_tool()` dispatchers whose `if name == "…"` / `match` arms become
  per-tool pseudo-functions, `{"name": handler}` tables.
- **JavaScript / TypeScript** (`code/javascript.py`): no parser in the standard library, so comments,
  strings, template literals and regex literals are masked (offsets preserved) and sinks are matched
  only when the file binds the module (`child_process`, `fs`, network libraries, `vm`, `dotenv`, …)
  or uses a global (`fetch`, `eval`, `new Function`, `process.env`, `Deno.*`, `Bun.*`). Handlers:
  the argument range of `server.tool("name", …)` / `registerTool`, `case "name":` arms of a
  `switch (name)`, `if (name === "name") {…}` blocks.
- **Attribution** follows calls through the package's own functions (depth ≤ 6) and is labelled
  `ast`, `lexical` or `none`. Minified files are noted and lower the confidence of TOOL-012.

Bounds: 3 000 files, 1 MiB per file, 40 MiB total; `node_modules`, tests, `.d.ts`, source maps and
minified bundles are skipped or noted. Snippets pass through the secret patterns of `redaction.py`
and the scan's `Redactor` before they are stored.

### 8.4 Rules

`CFG-018` install hook, `CFG-019` runtime code loading, `CFG-020` drift against the lock,
`TOOL-012` catalogue claim versus handler code. Catalogues are matched to manifests by normalised
server label (`demo-node` ≡ `Demo Node` ≡ `demo_node`) or by the package's last name segment.

### 8.5 Lock (`lock.py`)

```
{ "lock_version": 1, "tool": {…}, "generated_at": …,
  "servers": { "<name>": {
      "source_file", "launch",
      "package": { "ecosystem", "name", "version", "root", "digest", "files_scanned", "attribution" } | null,
      "capabilities": { "package": [class…], "tools": { "<tool>": [class…] } },
      "install_hooks": { "<script>": "<command>" },
      "catalogue": { "source_file", "tools": { "<tool>": { "digest", "raw": {canonical fields} } } } | null
  } } }
```

`mcp-trustcheck lock <paths>` writes it (default `mcp-trustcheck.lock.json`); `verify <paths>`
runs CFG-020 and TOOL-006 only; `scan --lock FILE` runs everything. The root key `lock_version`
matches no config or catalogue shape, so a lock left beside a config is skipped, never mis-read.

### 8.6 Report

Schema 1.2 adds `scan.lock`, `summary.by_standard` (findings per CWE / OWASP identifier) and a
top-level `packages` array with one `analysed` manifest or `not_located` record per server. The
terminal report prints a *Server capabilities* block before the findings table.
