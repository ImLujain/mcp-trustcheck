# Security policy

`mcp-trustcheck` reads attacker-influenced files, so bugs in it are security bugs. Please report:

- any input that makes the scanner execute something, open a network connection, write a file other
  than `--output`, hang, or crash with a traceback;
- any way a value from a scanned file reaches the terminal or JSON report without redaction or
  control-character sanitisation;
- a path-handling flaw that reads a file outside the user-supplied roots without `--follow-symlinks`;
- a false negative in a **weakness**-kind rule that you can demonstrate with a fixture.

## How to report

Open a private vulnerability report on the GitHub repository (Security → Report a vulnerability), or
open a normal issue if the problem is not exploitable. Include the input (synthetic, never a real
config with real secrets), the command line, and the observed output.

## What to expect

This is a research project maintained in spare time. Acknowledgement within a week; a fix or a
documented decision within a month for anything in the first three bullets. Credit in `CHANGELOG.md`
unless you prefer otherwise.

## Scope notes

- Heuristic false positives/negatives in **indicator**-kind rules (TOOL-001, TOOL-002, TOOL-004,
  TOOL-005, CFG-002, CFG-008) are welcome as issues but are not vulnerabilities.
- The documented residual risks in `docs/security-review.md` §3 are known.
