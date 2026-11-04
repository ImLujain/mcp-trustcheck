# Limitations

What `mcp-trustcheck` does **not** establish. These statements are repeated, in short form, in the README
and in every report footer, because a security tool that overstates its reach is itself a hazard.

## Static analysis boundaries

1. **It cannot determine that a tool or server is malicious.** TOOL-001/002/004/005 are lexical and
   structural *indicators*. A hit means "a human should read this"; a clean result means "nothing in
   our pattern set matched", not "safe". A determined author can paraphrase, translate, or split an
   instruction across fields.
2. **It cannot detect indirect prompt injection** (threat T4). Whether a model follows instructions
   found in a web page, issue, or email is a property of the model and the client, not of any file
   on disk. TOOL-008 only enumerates which tools import external content and which have side effects.
3. **It cannot verify server implementations.** Command-injection and path-traversal bugs (T7), token
   passthrough, confused-deputy flaws and SSRF in OAuth discovery (T8) live in server source code or
   runtime behaviour. A config that passes every check can still launch a vulnerable server. TOOL-005
   flags the *shape* of such bugs (free-form `command`/`sql`/`path` strings), nothing more.
4. **It never observes a live server.** Rug-pull detection (TOOL-006) compares two snapshots the user
   supplies; it does not watch `notifications/tools/list_changed`, cache expiry, or behaviour that
   changes while definitions stay identical. Live monitoring is a documented future enhancement that
   would require explicit authorisation and network access, which the tool currently refuses by design.

## Input coverage

5. **Config dialects are client conventions, not protocol.** The `mcpServers` family and VS Code
   `servers`/`inputs` are understood; approval keys (`autoApprove`, `alwaysAllow`, `trust`) are
   client-specific. Unknown keys are preserved and listed as unparsed, never assumed safe. Server-side
   framework settings, Docker Compose files, YAML/TOML configs and client settings files that hold
   approvals elsewhere are not read.
6. **Only JSON files are considered**, chosen by structural shape, never by file name.
7. **Cross-file precedence is not modelled.** Which of a user-level and a project-level config wins
   is client-specific; CFG-014 only reports duplicates within one file.
8. **Windows paths are matched as strings**, not resolved; `%VAR%` and `${…}` references are treated
   as non-literal and skipped by the path and secret checks.

## Heuristics

9. **Secret detection:** known-prefix matches are reliable; key-name and entropy matches are
   heuristics that can flag opaque identifiers and miss low-entropy passwords. Redaction protects the
   report, it does not protect the original file.
10. **Capability inference** (TOOL-004, TOOL-008) reads verbs in names and first sentences.
    `remove_filter` looks destructive; `run_report` looks like execution. Confidence is lowered when
    the inference comes from a description rather than a name.
11. **Package pinning** (CFG-001) limits drift; it does not vouch for the pinned version.
12. **Dangerous-content patterns** (CFG-004) are idioms, not a parser. Obfuscated or split commands
    pass through.

## Severity is not risk

13. Severity is the impact *if the finding is true*; confidence is how sure the detection is. Neither
    is a CVSS score, and there is deliberately no aggregate number. A finding describes a configuration
    weakness or an indicator — it is not a claim that the weakness is exploitable in the user's
    environment.

## Protocol version

14. Rules are written against MCP `2026-07-28`. Where a rule depends on that revision (`x-mcp-header`,
    the stateless core, the deprecation registry) its `spec_note` says so; clients and servers in the
    wild run mixed versions, and a finding may not apply to an older deployment.

## The tool itself

15. See `docs/security-review.md` for the residual risks of running the scanner on hostile input:
    heuristic redaction, path disclosure in reports, a narrowed-but-present symlink race, and an
    empirical (not proven) regex timing guarantee.
