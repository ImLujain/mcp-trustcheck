# Security review of mcp-trustcheck itself (Phase 5)

**Date:** 2026-11-02 · **Scope:** `src/mcp_trustcheck` at the end of Phase 4, re-tested after the fixes below.

A scanner that reads attacker-influenced files is itself an attack surface. This review treats
`mcp-trustcheck` as the target: what can a hostile input do to the person running it, and what controls
exist. Every item marked *fixed* has a regression test in `tests/unit/test_hardening.py` or
`tests/unit/test_self_security.py`.

## 1. Threat model for the tool

| Attacker goal | Vector | Status |
|---|---|---|
| Run code on the auditor's machine | Config entries contain commands; tool descriptions contain instructions | **Mitigated by design.** No `subprocess`, `socket`, `eval`, `exec` in `src/`; enforced by an AST-level test. Only `urllib.parse` (a pure parser) is allowed. |
| Exfiltrate the scanned config | Tool "phones home" | **Mitigated by design.** No network modules; stdlib only, no runtime dependencies. |
| Read files outside what the user intended | Symlinks inside a scanned tree; path traversal in inputs | **Mitigated.** Discovered symlinks resolving outside the user-supplied roots are skipped unless `--follow-symlinks`; the resolved target is opened (not the link) to narrow the TOCTOU window. An explicit input that is a symlink is followed, because the user named it. |
| Leak secrets through the report | Evidence snippets, descriptions, logs | **Mitigated.** Every snippet/description passes through the scan-wide `Redactor` at Finding construction; known secrets are replaced by `prefix…[redacted N chars]`. Integration test asserts none of the fixture secrets appear in any renderer's output. |
| Forge or hide report lines in the auditor's terminal | ANSI/OSC escape sequences and control characters in server names, tool names, descriptions, evidence | **Found and fixed (Phase 5).** Before the fix a server named `srv\x1b[0m\nFAKE LINE` injected a fake line and `\x1b[2J` cleared the screen. Now all C0/C1 controls are rendered as visible escapes (`\x1b`) at the redaction boundary and again in the terminal renderer; newlines in names are shown as `\n`. JSON output was already safe (serialiser escaping). |
| Hang or crash the scanner | Deeply nested JSON, huge catalogues, regex backtracking, FIFOs, device files, enormous trees | **Fixed/limited.** Explicit iterative depth gauge (`MAX_DEPTH = 200` containers) after parse, independent of the interpreter's recursion limit; `--max-file-size` (2 MiB) read cap; `--max-files` (5000) walk cap; non-regular files skipped before any `open()`; every compiled regex in the package is exercised against pathological 20 kB inputs in a timing test (< 0.5 s each). 6,000 tools scan in ~0.7 s. |
| Make the scanner write somewhere unexpected | `--output` pointing into a scanned directory or a symlinked location | **Mitigated.** `--output` is refused if it resolves inside any scanned directory; it is the only write the tool performs. |
| Hide findings by crashing one rule | Malformed definitions that trip an edge case in a check | **Fixed (Phase 5).** Each rule runs under an isolation boundary; a raising rule is recorded in `scan.errors[]` (JSON) and in a red block (terminal) and the remaining rules still run. |
| Exhaust the auditor's attention | Thousands of low-value findings | **Limited.** Severity/confidence filters (`--min-confidence`, `--fail-on`), per-rule selection, and the info/indicator/weakness `kind` separation. Not a security control. |

## 2. Controls, by layer

**Input layer (`discovery.py`).** Resolve inputs strictly; walk without following symlinks by default; skip `.git`, `node_modules`, caches; consider only `*.json`; regular files only; size cap before read; NUL-byte and UTF-8 checks; `json.loads` with `RecursionError` caught; explicit depth gauge; structural kind detection (file names are hints, never trusted); every failure becomes a `SkippedFile` with a reason.

**Analysis layer (`checks/`).** Pure functions over normalised data; no I/O; the only shared mutable state is `Context.state` and `Context.errors`. A rule can only read the already-parsed objects.

**Output layer (`redaction.py`, `report/`).** Secrets are classified in a pre-pass (`collect_sensitive_values`) so that *every* rule's evidence is scrubbed, not just the secrets rule. Snippets are capped at 512 chars, whitespace-collapsed, control-sanitised. The terminal renderer sanitises names, paths and notes again (defence in depth). JSON output is produced by `json.dumps`.

**Process layer.** Exit codes are deterministic; internal errors never print a traceback unless `-v`; the tool never modifies a scanned file.

## 3. Residual risks (accepted, documented)

1. **Secret detection is heuristic.** A credential with no known prefix and a non-suggestive key name is not redacted. Redaction is a safety net for reports, not a guarantee.
2. **Paths may disclose usernames.** Reports show scanned paths relative to the working directory, or absolute when outside it. A report shared publicly can reveal `/Users/<name>/…`.
3. **TOCTOU on symlinks is narrowed, not eliminated.** A race between `resolve()` and `open()` could still read an unintended file; the read is bounded to 2 MiB and nothing is executed.
4. **Regex timing test is empirical.** It demonstrates absence of catastrophic backtracking on the chosen inputs; it is not a proof.
5. **Tool names, server names and JSON paths are not redacted**, only control-sanitised. A secret used *as a key name* would appear in the report.
6. **`--follow-symlinks` and explicit symlink inputs are user-authorised reads.** They can reach anything the user can read.

## 4. What was tested

| Probe | Result before | Result after |
|---|---|---|
| ANSI/OSC in server name, tool name, description, evidence | Forged lines, screen clear | Visible `\x1b` escapes; single-line names |
| 6,000-tool catalogue (1.3 MB) | 0.7 s, 6,007 findings | unchanged |
| 20 kB adversarial strings against every regex | all < 0.1 s | timing test added |
| 300/450-level nested schema | scanned (near the interpreter limit) | skipped as `too_deep` above 200 containers |
| 600+/900-level nested schema | `too_deep` via `RecursionError` | `too_deep` via gauge |
| FIFO named `*.json` | skipped as `empty` (by luck) | skipped as `not_regular_file` before `open()` |
| Symlink to `/etc/hostname` inside a scanned tree | skipped | unchanged |
| Symlink to `/etc/hostname` passed as the input | read (user intent) | unchanged, documented |
| 12 files with `--max-files 5` | n/a | 5 scanned, `too_many_files` recorded |
| Rule raising an exception | exit 3, no findings | other rules' findings kept; error reported |

## 5. Not in scope of this review

Supply-chain integrity of the repository itself (signing, SBOM), and the security of the CI workflow, are left for the publication phase.
