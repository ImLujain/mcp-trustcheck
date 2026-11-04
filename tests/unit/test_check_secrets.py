from __future__ import annotations

from conftest import run_rule
from mcp_trustcheck.model import Confidence, Severity

GHP = "ghp_FAKE0000000000000000000000000000FAKE"
AWS = "AKIAIOSFODNN7EXAMPLE"


def _env(env: dict[str, object]) -> dict:  # type: ignore[type-arg]
    return {"mcpServers": {"s": {"command": "npx", "args": ["-y", "pkg@1.0.0"], "env": env}}}


def test_known_prefix_high_confidence_and_redacted() -> None:
    f = run_rule("CFG-005", _env({"GITHUB_TOKEN": GHP}))
    assert len(f) == 1
    assert f[0].confidence is Confidence.HIGH and f[0].severity is Severity.HIGH
    assert GHP not in f[0].evidence[0].snippet and GHP not in f[0].description
    assert f[0].evidence[0].snippet.startswith("ghp_…")


def test_cloud_root_key_is_critical() -> None:
    f = run_rule("CFG-005", _env({"AWS_ACCESS_KEY_ID": AWS}))
    assert f[0].severity is Severity.CRITICAL


def test_key_name_match_is_medium_confidence() -> None:
    f = run_rule("CFG-005", _env({"DB_PASSWORD": "correct-horse-battery-staple-9"}))
    assert f[0].confidence is Confidence.MEDIUM


def test_references_and_placeholders_are_ignored() -> None:
    assert (
        run_rule(
            "CFG-005",
            _env(
                {
                    "A": "${env:TOKEN}",
                    "B": "${input:x}",
                    "C": "$TOKEN",
                    "D": "%TOKEN%",
                    "API_KEY": "<your-api-key>",
                    "SECRET": "",
                    "TOKEN": "xxxxxxxxxxxxxxxxxx",
                    "PASSWORD": "changeme",
                }
            ),
        )
        == []
    )


def test_bare_arguments_do_not_trip_entropy_heuristic() -> None:
    cfg = {
        "mcpServers": {
            "s": {
                "command": "npx",
                "args": [
                    "-y",
                    "@modelcontextprotocol/server-filesystem@2026.1.0",
                    "C:\\Users\\alice\\Projects\\app\\dev.db",
                    "--pattern",
                    "a1B2c3D4e5F6g7H8i9J0k1L2m3N4",
                    "TODO|FIXME",
                ],
            }
        }
    }
    assert run_rule("CFG-005", cfg) == []


def test_flag_value_and_kv_argument_are_checked() -> None:
    cfg = {"mcpServers": {"s": {"command": "x", "args": ["--api-key", GHP, f"token={AWS}"]}}}
    f = run_rule("CFG-005", cfg)
    assert {x.evidence[0].json_path for x in f} == {
        "$.mcpServers.s.args[1]",
        "$.mcpServers.s.args[2]",
    }


def test_headers_and_url_credentials() -> None:
    cfg = {
        "mcpServers": {
            "r": {
                "url": f"https://user:{GHP}@h.example.com/mcp?api_key={AWS}",
                "headers": {"Authorization": f"Bearer {GHP}", "X-Trace": "abc"},
            }
        }
    }
    f = run_rule("CFG-005", cfg)
    origins = {e.note for x in f for e in x.evidence}
    assert any("url userinfo" in (o or "") for o in origins)
    assert any("url query parameter 'api_key'" in (o or "") for o in origins)
    assert any("header 'Authorization'" in (o or "") for o in origins)
    assert all(GHP not in e.snippet and AWS not in e.snippet for x in f for e in x.evidence)


def test_other_rules_evidence_is_scrubbed_too() -> None:
    """A secret in a shell payload must not leak through CFG-003's evidence."""
    cfg = {
        "mcpServers": {
            "s": {"command": "bash", "args": ["-c", f"TOKEN={GHP} npx foo && echo done"]}
        }
    }
    f = run_rule("CFG-003", cfg)
    assert f and GHP not in f[0].evidence[0].snippet
