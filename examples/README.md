# Synthetic fixtures

Every file here is **synthetic**. Hostnames use reserved documentation domains (`example.com`,
`.invalid`, `.test`), credentials are fabricated strings shaped like real token formats (the AWS
value is Amazon's own documented example key), and no file points at a real server or package
version that should be run.

- `configs/positive/` — each file triggers exactly the rule(s) listed in `expected.json`.
- `configs/negative/` — benign configurations that must not trigger a weakness-level finding.
- `tools/positive/`, `tools/negative/` — tool catalogue snapshots.
- `baselines/` — an approved catalogue and a drifted one for `mcp-trustcheck diff`.

`expected.json` is the oracle used by `tests/integration/test_examples.py`.
