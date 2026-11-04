"""Input discovery: path validation, directory walking, size/type gating (design.md §6).

Guarantees: files are opened read-only; symlinks that resolve outside the user-supplied roots are
skipped unless `follow_symlinks`; oversized, binary, empty, malformed and too-deeply-nested JSON
become `SkippedFile` entries rather than exceptions.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp_trustcheck.loaders import detect_kind
from mcp_trustcheck.model import SkippedFile

DEFAULT_MAX_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_FILES = 5000
MAX_DEPTH = 200  # far beyond any legitimate config or JSON Schema; keeps recursive walkers safe
SKIP_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "dist",
        "build",
        ".tox",
        ".idea",
    }
)


@dataclass
class LoadedFile:
    path: Path
    display: str
    kind: str
    dialect: str
    data: Any


@dataclass
class DiscoveryResult:
    loaded: list[LoadedFile]
    skipped: list[SkippedFile]
    roots: list[Path]


def nesting_depth(obj: Any, limit: int = MAX_DEPTH) -> int:
    """Number of nested containers (dict/list), measured iteratively; stops once `limit` is exceeded."""
    depth = 0
    stack: list[tuple[Any, int]] = [(obj, 1)] if isinstance(obj, (dict, list)) else []
    while stack:
        node, d = stack.pop()
        if d > depth:
            depth = d
            if depth > limit:
                return depth
        children = node.values() if isinstance(node, dict) else node
        stack.extend((v, d + 1) for v in children if isinstance(v, (dict, list)))
    return depth


def _display(path: Path, roots: list[Path]) -> str:
    cwd = Path.cwd()
    try:
        return str(path.relative_to(cwd))
    except ValueError:
        return str(path)


def _within(path: Path, roots: list[Path]) -> bool:
    return any(path == r or r in path.parents for r in roots)


def _iter_candidates(root: Path, follow_symlinks: bool) -> list[Path]:
    if root.is_file():
        return [root]
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fn in sorted(filenames):
            if fn.lower().endswith(".json"):
                out.append(Path(dirpath) / fn)
    return out


def load_one(
    path: Path, roots: list[Path], *, max_bytes: int, follow_symlinks: bool
) -> LoadedFile | SkippedFile:
    display = _display(path, roots)
    try:
        target = path
        if path.is_symlink():
            target = path.resolve(strict=True)
            if not follow_symlinks and not _within(target, roots):
                return SkippedFile(display, "symlink_outside_root", str(target))
        if not target.is_file():
            return SkippedFile(display, "not_regular_file")
        size = target.stat().st_size
        if size == 0:
            return SkippedFile(display, "empty")
        if size > max_bytes:
            return SkippedFile(display, "too_large", f"{size} bytes > {max_bytes}")
        # Open the resolved target that was just checked, not the symlink, to narrow the TOCTOU window.
        with target.open("rb") as fh:
            raw = fh.read(max_bytes + 1)
    except OSError as exc:
        return SkippedFile(display, "unreadable", exc.strerror or str(exc))

    if b"\x00" in raw:
        return SkippedFile(display, "binary")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return SkippedFile(display, "binary", "not valid UTF-8")
    if not text.strip():
        return SkippedFile(display, "empty")
    try:
        data = json.loads(text)
    except RecursionError:
        return SkippedFile(display, "too_deep")
    except json.JSONDecodeError as exc:
        return SkippedFile(display, "invalid_json", f"line {exc.lineno} col {exc.colno}: {exc.msg}")

    if nesting_depth(data) > MAX_DEPTH:
        return SkippedFile(display, "too_deep", f"nesting exceeds {MAX_DEPTH}")
    kind = detect_kind(data)
    if kind is None:
        return SkippedFile(display, "not_recognised")
    return LoadedFile(path=path, display=display, kind=kind[0], dialect=kind[1], data=data)


def discover(
    inputs: list[str],
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    follow_symlinks: bool = False,
    max_files: int = DEFAULT_MAX_FILES,
) -> DiscoveryResult:
    roots: list[Path] = []
    skipped: list[SkippedFile] = []
    for raw in inputs:
        p = Path(raw)
        try:
            roots.append(p.resolve(strict=True))
        except OSError:
            skipped.append(SkippedFile(raw, "unreadable", "no such file or directory"))

    loaded: list[LoadedFile] = []
    seen: set[Path] = set()
    for root in roots:
        for cand in _iter_candidates(root, follow_symlinks):
            if cand in seen:
                continue
            if len(seen) >= max_files:
                skipped.append(
                    SkippedFile(
                        _display(root, roots), "too_many_files", f"stopped after {max_files} files"
                    )
                )
                break
            seen.add(cand)
            result = load_one(cand, roots, max_bytes=max_bytes, follow_symlinks=follow_symlinks)
            if isinstance(result, LoadedFile):
                loaded.append(result)
            else:
                skipped.append(result)
    return DiscoveryResult(loaded=loaded, skipped=skipped, roots=roots)
