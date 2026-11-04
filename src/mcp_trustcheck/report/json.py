"""JSON renderer producing the Report object (schema: docs/schema/report.schema.json)."""

from __future__ import annotations

import json

from mcp_trustcheck.model import Report


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False, sort_keys=False) + "\n"
