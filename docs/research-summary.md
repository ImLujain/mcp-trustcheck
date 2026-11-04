# Research summary: what mcp-trustcheck demonstrates, and what it does not

**Project:** mcp-trustcheck 0.1.0 · **Date:** 2026-11-02 · **Spec baseline:** MCP 2026-07-28

## The question

How much of the MCP attack surface described in the specification's security guidance and in
published research (tool poisoning, rug pulls, shadowing, over-privileged local servers,
credential exposure, insecure transport, bypassed consent) is visible *statically*, in the files a
developer already has on disk, before any server runs — and can it be reported with enough
rigour that a practitioner can trust the result and understand its limits?

## What was built

A Python CLI (stdlib only, ~6,600 lines including tests) that reads MCP client configuration files
and tool-catalogue snapshots and runs 23 checks, each tied to a normative statement in the MCP
specification, a documented attack class, or an explicitly stated hypothesis. Findings carry a
severity (impact if true) and a confidence (how deterministic the detection is) as separate
values, a kind (weakness / indicator / info), redacted evidence with a JSON path, the impact,
the mitigation, the references and the rule's own limitation text.

The project was built in six phases with primary-source verification first: the threat model was
written against the current specification revision (2026-07-28 — the stateless core, the removal
of protocol sessions, `x-mcp-header`, the opt-in `subscriptions/listen` stream) before any code,
and each later phase validated the previous one.

## What the results show

**1. A large share of the documented MCP attack surface is detectable from static artefacts with
high confidence.** Of the 23 checks, 14 are rated high-confidence by default: shell wrappers and
dangerous command idioms in launch lines, known-prefix credentials, privileged container flags,
plaintext remote transport, auto-approval wildcards, invalid or sensitive `x-mcp-header`
declarations, baseline drift, and exact-name collisions. These correspond to concrete MUST/SHOULD
statements in the specification or to the explicit examples in its security best-practices page.
On the 34-file synthetic corpus, every positive fixture triggers exactly the intended rule and
severity, and no benign fixture produces anything above `low` — verified by an integration test
against a hand-reviewed oracle, not by inspection of a demo.

**2. Contextual rules eliminate the false positives that keyword scanners produce, and the
corpus proves it.** The same `|` character is Info in the argv of a directly spawned process,
High inside `bash -c`, and absent from a Windows `cmd /c npx …` wrapper's verdict (Low). The
entropy heuristic, applied naively to all values, flagged package specs and Windows paths on the
very first run; restricting it to env/header/URL values with a token shape removed every such
false positive while keeping every true one. Those two design decisions are the difference between
a tool people run in CI and one they disable after a day.

**3. Tool poisoning is detectable as an *indicator*, with graded confidence, and should not be
claimed as more.** Scoring six independent signal classes across all strings in a tool definition
(including parameter descriptions, enum values and output schemas) correctly grades the canonical
Invariant Labs payload as High, a cross-tool recipient-rewrite as High, and a lone "you should pass
an ISO date" as Low/Low. The rule is lexical. It will miss paraphrase and other languages, and the
documentation says so in every finding.

**4. A scanner that reads hostile input is itself a target, and the review found real bugs.** An
adversarial pass against the tool produced two defects worth a CVE class in a larger product:
server and tool names could inject ANSI/OSC sequences into the terminal report (forging lines,
clearing the screen), and a single raising rule aborted the whole scan with no report. Both were
fixed with regression tests, alongside an explicit nesting-depth limit, a regular-file guard, a
file-count cap and a timing test over every compiled regular expression. The tool's "never
executes, never connects" claim is enforced by an AST scan of its own source in the test suite.

**5. The specification revision matters for what a check means.** Session hijacking (≤ 2025-11-25)
became state-handle hijacking in 2026-07-28; `x-mcp-header` did not exist before 2026-07-28; the
HTTP+SSE transport moved from "deprecated in prose" to a formal Deprecated state with a
twelve-month window. Checks that depend on a revision say so in their `spec_note`.

## What the results do not establish

- **That any real-world deployment is vulnerable.** All inputs are synthetic. The corpus
  demonstrates detection behaviour, not prevalence.
- **That a tool flagged by TOOL-001/002/004/005 is malicious**, or that one not flagged is safe.
- **Anything about runtime behaviour**: indirect prompt injection through tool *results*, command
  injection inside server code, token passthrough, confused-deputy flaws, SSRF during OAuth
  discovery, or live definition changes. Each is named in the threat model with the reason it is
  out of static reach and what a dynamic extension would need.
- **Exploitability.** A finding is a configuration weakness or an indicator. Severity is impact if
  true, not likelihood, and the tool deliberately produces no aggregate score.
- **Completeness of dialects.** Two config dialects are parsed; approval keys are client-specific;
  cross-file precedence is not modelled.

## Numbers that are reproducible from the repository

| | |
|---|---|
| Checks | 23 (15 configuration, 8 tool-definition) |
| Default confidence | 14 high · 7 medium · 2 low |
| Fixtures | 34 scanned (18 positive, 11 negative, 2 baselines, 3 robustness-skipped) + 5 skipped |
| Findings on `examples/` | 90: 6 critical, 34 high, 24 medium, 12 low, 14 info |
| Tests | 99 (unit, integration, hardening, docs-in-sync, self-security) |
| Runtime dependencies | 0 |
| Scan throughput | 6,000-tool catalogue in ~0.7 s |

## Where this should go next

The highest-value extension is not more static rules; it is a **safe, opt-in dynamic layer**:
connect to a declared server with explicit authorisation, snapshot its `tools/list`, and alert on
`list_changed` or cache-TTL re-fetches that change a hash — turning TOOL-006 from an offline diff
into continuous rug-pull detection. Second is **source-level taint analysis** for argument → shell
sinks in server code, where most of the published MCP CVEs live. Both are documented as future
work with the preconditions they would need.
