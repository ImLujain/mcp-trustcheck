# Contributing

Thanks for looking. This is a small research tool; contributions that keep it small, reviewable and
honest about its limits are the most welcome.

## Setting up

```bash
git clone https://github.com/ImLujain/mcp-trustcheck
cd mcp-trustcheck
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
ruff check . && ruff format --check . && mypy && pytest
```

Python ≥ 3.10. The package has **no runtime dependencies** and that is a design constraint, not an
accident (see `docs/security-review.md`): a PR that adds one needs a very good reason.

## Adding or changing a check

Every rule has five parts, and a PR that touches a rule should touch all five:

1. **Metadata** in `src/mcp_trustcheck/rules_catalog.py` — property, threat ID, kind, default
   severity/confidence, impact, mitigation, limitations, references (primary sources preferred:
   the MCP specification, RFCs, published research with a URL).
2. **Implementation** in `src/mcp_trustcheck/checks/config/` or `checks/tools/` — a pure function
   registered with `@register("ID", scope)`. No I/O, no subprocess, no network; `tests/unit/test_self_security.py`
   enforces this with an AST scan.
3. **Fixtures** in `examples/` — at least one positive file that triggers the rule and one benign
   file that must not. Fixtures are synthetic: reserved documentation domains, fabricated token
   shapes, no real packages pinned to versions anyone should run.
4. **Oracle** — add the expected `RULE@severity` entries to `examples/expected.json`. The integration
   test checks exact multiplicity, so review the scan output by hand before updating it.
5. **Methodology notes** — add the rule's entry to `NOTES` in `scripts/gen_methodology.py` and run
   `python scripts/gen_methodology.py > docs/methodology.md`. A test fails if the doc is stale.

Also add the rule to the proposed-checks table in `docs/threat-model.md` §6 (a test checks this).

## Rules of thumb

- Separate **severity** (impact if true) from **confidence** (how sure the detection is). Do not
  invent a numeric score.
- Prefer contextual logic over keyword matching (e.g. metacharacters only matter when a shell is the
  command). Document the false-positive and false-negative modes you know about.
- If the check needs to run a command or talk to a server, it does not belong in this tool as it
  stands; file an issue describing it as a future dynamic check.
- Never print a value that could be a secret. Build evidence through `checks.emit`, which redacts.

## Reporting problems

Bugs and false positives: GitHub issues. Anything that could be a vulnerability in the scanner
itself: see `SECURITY.md`.
