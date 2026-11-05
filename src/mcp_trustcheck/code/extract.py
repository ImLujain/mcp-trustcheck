"""Walk a located package, analyse each source file, and assemble a `PackageManifest`.

Bounded and read-only: at most `max_files` files, `max_file_bytes` per file and `max_total_bytes`
overall are read; test directories, type declarations, source maps and `node_modules` are skipped.
Per-tool capabilities are the transitive closure of the handler's calls over the package's own
functions, followed up to `MAX_DEPTH` levels.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections import deque
from pathlib import Path

from mcp_trustcheck.code.common import FunctionInfo, ModuleResult
from mcp_trustcheck.code.javascript import analyse_javascript
from mcp_trustcheck.code.locate import Located, SearchRoots, locate
from mcp_trustcheck.code.model import PackageManifest, Sink, ToolCapabilities, UnlocatedPackage
from mcp_trustcheck.code.python import analyse_python
from mcp_trustcheck.model import ServerConfig

MAX_FILES = 3000
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 40 * 1024 * 1024
MAX_DEPTH = 10
MAX_CANDIDATES = 6  # same-named functions followed per call when no module hint resolves

PY_SUFFIXES = (".py",)
JS_SUFFIXES = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx")
SKIP_DIRS = frozenset(
    {
        "node_modules",
        ".git",
        "__pycache__",
        ".venv",
        "venv",
        "test",
        "tests",
        "__tests__",
        "__mocks__",
        "spec",
        "coverage",
        ".nyc_output",
        "docs",
        "doc",
        ".github",
        "fixtures",
        "__fixtures__",
    }
)
_SKIP_FILE_RE = re.compile(
    r"(?:\.d\.ts|\.map|\.min\.js|\.test\.[cm]?[jt]sx?|\.spec\.[cm]?[jt]sx?)$|^test_.*\.py$|_test\.py$|^conftest\.py$"
)
# `prepare` is deliberately absent: npm runs it for local checkouts and git dependencies, not when a
# published tarball is installed from the registry, so it never fires for an `npx pkg` launch.
INSTALL_HOOKS = ("preinstall", "install", "postinstall")


def _iter_files(paths: list[Path], root: Path) -> list[Path]:
    out: list[Path] = []
    for p in paths:
        if p.is_file():
            out.append(p)
            continue
        for dirpath, dirnames, filenames in os.walk(p):
            dirnames[:] = sorted(
                d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")
            )
            for fn in sorted(filenames):
                if fn.endswith(PY_SUFFIXES + JS_SUFFIXES) and not _SKIP_FILE_RE.search(fn):
                    out.append(Path(dirpath) / fn)
            if len(out) > MAX_FILES:
                return out
    return out


def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


def _package_metadata(located: Located) -> tuple[dict[str, str], list[str]]:
    hooks: dict[str, str] = {}
    notes: list[str] = []
    pj = located.root / "package.json"
    if located.ecosystem in ("npm", "path") and pj.is_file():
        try:
            data = json.loads(pj.read_text(encoding="utf-8", errors="replace"))
            scripts = data.get("scripts") if isinstance(data, dict) else None
            if isinstance(scripts, dict):
                for k in INSTALL_HOOKS:
                    v = scripts.get(k)
                    if isinstance(v, str) and v.strip():
                        hooks[k] = v.strip()
        except (OSError, ValueError):
            notes.append("package.json could not be parsed")
    setup = located.root / "setup.py"
    if setup.is_file():
        try:
            text = setup.read_text(encoding="utf-8", errors="replace")[:200_000]
            if "cmdclass" in text:
                hooks["setup.py"] = "custom cmdclass (code runs at install time)"
        except OSError:
            pass
    return hooks, notes


# ------------------------------------------------------------------------------- resolution


class _Resolver:
    def __init__(self, modules: list[ModuleResult]) -> None:
        self.by_key: dict[str, FunctionInfo] = {}
        self.by_name: dict[str, list[FunctionInfo]] = {}
        self.by_mod: dict[tuple[str, str], FunctionInfo] = {}
        for m in modules:
            for info in m.functions.values():
                self.by_key[info.key] = info
                self.by_name.setdefault(info.name, []).append(info)
                self.by_mod[(m.module_name, info.name)] = info

    def lookup(self, ref: str) -> FunctionInfo | None:
        if ref in self.by_key:
            return self.by_key[ref]
        cands = self.by_name.get(ref, [])
        return cands[0] if len(cands) == 1 else (cands[0] if cands else None)

    def targets(self, call: str, caller: FunctionInfo | None = None) -> list[FunctionInfo]:
        if call in self.by_key:  # an exact function key (inline handler inside a tool object)
            return [self.by_key[call]]
        if "|" in call:
            hint, name = call.split("|", 1)
            hit = self.by_mod.get((hint, name))
            if hit is not None:
                return [hit]
        else:
            name = call
        cands = self.by_name.get(name, [])
        if caller is not None:
            cands = sorted(cands, key=lambda f: f.file != caller.file)  # same file first
        return cands[:MAX_CANDIDATES]

    def reach(self, start: FunctionInfo) -> tuple[list[Sink], int]:
        seen = {start.key}
        queue: deque[tuple[FunctionInfo, int]] = deque([(start, 0)])
        sinks: list[Sink] = []
        depth = 0
        while queue:
            info, d = queue.popleft()
            depth = max(depth, d)
            sinks.extend(info.sinks)
            if d >= MAX_DEPTH:
                continue
            for call in sorted(info.calls):
                for tgt in self.targets(call, info):
                    if tgt.key not in seen:
                        seen.add(tgt.key)
                        queue.append((tgt, d + 1))
        uniq: dict[tuple[str, str, int, str], Sink] = {}
        for s in sinks:
            uniq.setdefault((s.cls, s.file, s.line, s.callee), s)
        return sorted(uniq.values(), key=lambda s: (s.file, s.line, s.cls)), depth


# ------------------------------------------------------------------------------- driver


def analyse(
    server: ServerConfig,
    located: Located,
    *,
    max_files: int = MAX_FILES,
    max_file_bytes: int = MAX_FILE_BYTES,
    max_total_bytes: int = MAX_TOTAL_BYTES,
) -> PackageManifest:
    root = located.root
    files = _iter_files(located.paths, root)
    notes: list[str] = []
    if len(files) > max_files:
        notes.append(f"only the first {max_files} of {len(files)} source files were read")
        files = files[:max_files]

    modules: list[ModuleResult] = []
    hasher = hashlib.sha256()
    total = 0
    n_py = n_js = 0
    for f in files:
        rel = _rel(f, root)
        try:
            size = f.stat().st_size
            if size > max_file_bytes:
                notes.append(f"{rel}: skipped ({size} bytes > {max_file_bytes})")
                continue
            if total + size > max_total_bytes:
                notes.append("size budget reached; remaining files were not read")
                break
            raw = f.read_bytes()
        except OSError as exc:
            notes.append(f"{rel}: unreadable ({exc.strerror or exc})")
            continue
        total += len(raw)
        hasher.update(
            rel.encode("utf-8") + b"\0" + hashlib.sha256(raw).hexdigest().encode() + b"\n"
        )
        text = raw.decode("utf-8", errors="replace")
        if f.suffix in PY_SUFFIXES:
            n_py += 1
            mod = analyse_python(rel, text)
            mod.module_name = f.stem
        else:
            n_js += 1
            mod = analyse_javascript(rel, text)
        modules.append(mod)
        notes.extend(mod.notes)

    resolver = _Resolver(modules)
    sinks: list[Sink] = [s for m in modules for s in m.sinks]
    tools: dict[str, ToolCapabilities] = {}
    declared: set[str] = set().union(*(m.declared for m in modules))
    attributions: set[str] = set()
    for m in modules:
        for name, ref in m.tools.items():
            if name in m.weak_tools and name not in declared:
                continue  # a `switch (metricName)` look-alike, not a tool this package declares
            info = resolver.lookup(ref)
            if info is None:
                tools.setdefault(name, ToolCapabilities(name=name, handler=""))
                continue
            reached, depth = resolver.reach(info)
            attributions.add(m.attribution)
            tc = tools.get(name)
            if tc is None:
                tools[name] = ToolCapabilities(
                    name=name, handler=f"{info.file}:{info.line}", sinks=reached, depth=depth
                )
            else:
                tc.sinks = sorted(
                    {(s.file, s.line, s.cls): s for s in [*tc.sinks, *reached]}.values(),
                    key=lambda s: (s.file, s.line, s.cls),
                )
    declared |= set(tools)

    if not tools:
        attribution = "none"
    elif attributions == {"ast"}:
        attribution = "ast"
    else:
        attribution = "lexical"
    hooks, meta_notes = _package_metadata(located)
    notes += meta_notes
    language = "mixed" if n_py and n_js else "python" if n_py else "javascript" if n_js else "none"
    if not files:
        notes.append("no Python or JavaScript source files found under the located path")

    try:
        root_display = str(root.relative_to(Path.cwd()))
    except ValueError:
        root_display = str(root)
    return PackageManifest(
        server=server.name,
        source_file=server.source_file,
        json_path=server.json_path,
        ecosystem=located.ecosystem,
        name=located.name,
        version=located.version,
        root=root_display,
        located_by=located.located_by,
        language=language,
        files_scanned=len(modules),
        bytes_scanned=total,
        digest=hasher.hexdigest(),
        attribution=attribution,
        sinks=sorted(sinks, key=lambda s: (s.file, s.line, s.cls)),
        tools=tools,
        declared_tools=sorted(declared),
        install_hooks=hooks,
        notes=sorted(set(notes)),
    )


def analyse_servers(
    servers: list[ServerConfig],
    config_dirs: dict[str, Path],
    *,
    overrides: dict[str, Path] | None = None,
    roots: SearchRoots | None = None,
) -> tuple[list[PackageManifest], list[UnlocatedPackage]]:
    manifests: list[PackageManifest] = []
    missing: list[UnlocatedPackage] = []
    for server in servers:
        if server.disabled:
            continue
        cfg_dir = config_dirs.get(server.source_file, Path.cwd())
        found = locate(server, config_dir=cfg_dir, overrides=overrides, roots=roots)
        if isinstance(found, UnlocatedPackage):
            missing.append(found)
        else:
            manifests.append(analyse(server, found))
    return manifests, missing
