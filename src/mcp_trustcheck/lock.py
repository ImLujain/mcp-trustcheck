"""The lock file: the reviewed state of every server, so `verify` can say what changed.

For each server the lock records the launch line, the located package (ecosystem, name, version,
content digest), the capability classes of the package and of each attributed tool, the install
hooks, and the approved tool catalogue when one was scanned alongside the config. It is JSON with
a `lock_version` root key, which no config or catalogue loader recognises, so a lock left next to
a config is skipped as `not_recognised` rather than mis-read.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp_trustcheck import __version__
from mcp_trustcheck.checks import norm_label
from mcp_trustcheck.checks.tools.drift import CANON_FIELDS, digest
from mcp_trustcheck.code.model import PackageManifest
from mcp_trustcheck.model import ServerConfig, ToolDefinition, ToolSet

LOCK_VERSION = 1
DEFAULT_LOCK_NAME = "mcp-trustcheck.lock.json"


class LockError(Exception):
    """The lock file is missing, unreadable or not a lock."""


def build_lock(
    servers: list[ServerConfig],
    manifests: dict[str, PackageManifest],
    toolsets: list[ToolSet],
) -> dict[str, Any]:
    catalogues = {norm_label(ts.server_label): ts for ts in toolsets}
    out: dict[str, Any] = {
        "lock_version": LOCK_VERSION,
        "tool": {"name": "mcp-trustcheck", "version": __version__},
        "generated_at": datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        "servers": {},
    }
    for s in servers:
        if s.disabled:
            continue
        m = manifests.get(s.name)
        entry: dict[str, Any] = {
            "source_file": s.source_file,
            "launch": s.command_line,
            "package": None,
            "capabilities": {"package": [], "tools": {}},
            "install_hooks": {},
            "catalogue": None,
        }
        if m is not None:
            entry["package"] = {
                "ecosystem": m.ecosystem,
                "name": m.name,
                "version": m.version,
                "root": m.root,
                "digest": m.digest,
                "files_scanned": m.files_scanned,
                "attribution": m.attribution,
            }
            entry["capabilities"] = {
                "package": sorted(m.classes),
                "tools": {
                    name: sorted(tc.classes) for name, tc in sorted(m.tools.items()) if tc.handler
                },
            }
            entry["install_hooks"] = dict(sorted(m.install_hooks.items()))
        ts = catalogues.get(norm_label(s.name)) or (
            catalogues.get(norm_label(m.name.rsplit("/", 1)[-1])) if m is not None else None
        )
        if ts is not None:
            entry["catalogue"] = {
                "source_file": ts.source_file,
                "tools": {
                    t.name: {
                        "digest": digest(t),
                        "raw": {k: t.raw[k] for k in CANON_FIELDS if k in t.raw},
                    }
                    for t in ts.tools
                },
            }
        out["servers"][s.name] = entry
    return out


def write_lock(path: Path, lock: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(lock, indent=2, ensure_ascii=False, sort_keys=False) + "\n", encoding="utf-8"
    )


def load_lock(path: str) -> dict[str, Any]:
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except OSError as exc:
        raise LockError(f"lock file not readable: {path} ({exc.strerror or exc})") from exc
    except ValueError as exc:
        raise LockError(f"lock file is not valid JSON: {path} ({exc})") from exc
    if (
        not isinstance(data, dict)
        or data.get("lock_version") != LOCK_VERSION
        or not isinstance(data.get("servers"), dict)
    ):
        raise LockError(
            f"{path} is not an mcp-trustcheck lock file (expected lock_version {LOCK_VERSION})"
        )
    return data


def baselines_from_lock(lock: dict[str, Any], lock_path: str) -> dict[str, ToolSet]:
    """One approved `ToolSet` per locked server that had a catalogue, keyed by normalised label."""
    out: dict[str, ToolSet] = {}
    for name, entry in lock["servers"].items():
        cat = entry.get("catalogue") if isinstance(entry, dict) else None
        if not isinstance(cat, dict) or not isinstance(cat.get("tools"), dict):
            continue
        ts = ToolSet(source_file=lock_path, server_label=str(name), shape="lock")
        for i, (tname, rec) in enumerate(cat["tools"].items()):
            raw = rec.get("raw") if isinstance(rec, dict) else None
            if not isinstance(raw, dict):
                continue
            raw = {"name": tname, **raw}
            ann = raw.get("annotations")
            ts.tools.append(
                ToolDefinition(
                    name=str(tname),
                    source_file=lock_path,
                    json_path=f"$.servers.{name}.catalogue.tools[{i}]",
                    server_label=str(name),
                    title=raw.get("title") if isinstance(raw.get("title"), str) else None,
                    description=raw.get("description")
                    if isinstance(raw.get("description"), str)
                    else None,
                    input_schema=raw.get("inputSchema")
                    if isinstance(raw.get("inputSchema"), dict)
                    else None,
                    output_schema=raw.get("outputSchema")
                    if isinstance(raw.get("outputSchema"), dict)
                    else None,
                    annotations=ann if isinstance(ann, dict) else {},
                    raw=raw,
                )
            )
        out[norm_label(str(name))] = ts
    return out
