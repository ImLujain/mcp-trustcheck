"""Find, on the local disk, the code a server entry would launch. Read-only, no network.

The client has already installed whatever it runs, so the code is usually present in a launcher
cache (`npx`, `bunx`, `pnpm dlx`, `uvx`, `pipx`), in a global `node_modules`, in a project
virtualenv, or at the script path named in the config. This module only looks in those places.
It never runs a launcher, never resolves a registry name over the network and never follows a
package's own install scripts. `--package-path NAME=DIR` lets the user point at code they fetched
themselves (for example an extracted `npm pack` tarball).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from mcp_trustcheck.checks._util import basename
from mcp_trustcheck.checks.config.packages import _NPM_SPEC, _PY_SPEC, package_spec
from mcp_trustcheck.code.model import UnlocatedPackage
from mcp_trustcheck.model import ServerConfig

SCRIPT_INTERPRETERS = frozenset(
    {"node", "nodejs", "deno", "bun", "tsx", "ts-node", "python", "python3", "python2", "py"}
)
SCRIPT_SUFFIXES = (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".py")
CONTAINER_LAUNCHERS = frozenset({"docker", "podman", "nerdctl"})
_PROJECT_MARKERS = ("package.json", "pyproject.toml", "setup.py", "setup.cfg")
_MAX_GLOB = 400  # upper bound on cache entries inspected per location


@dataclass
class Located:
    ecosystem: str  # "npm" | "pypi" | "path"
    name: str
    version: str | None
    root: Path  # directory shown in the report
    paths: list[Path]  # files/directories to read (subset of root)
    located_by: str
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass
class SearchRoots:
    """Every location consulted, so a 'not found' can say where it looked. Overridable in tests."""

    home: Path = field(default_factory=Path.home)
    env: dict[str, str] = field(default_factory=lambda: dict(os.environ))

    def _env_path(self, name: str) -> Path | None:
        v = self.env.get(name)
        return Path(v).expanduser() if v else None

    def npm_npx_caches(self) -> list[Path]:
        out: list[Path] = []
        cache = self._env_path("npm_config_cache") or self._env_path("NPM_CONFIG_CACHE")
        if cache:
            out.append(cache / "_npx")
        out.append(self.home / ".npm" / "_npx")
        local = self._env_path("LOCALAPPDATA")
        if local:
            out.append(local / "npm-cache" / "_npx")
        return out

    def npm_global_roots(self) -> list[Path]:
        out: list[Path] = []
        prefix = self._env_path("npm_config_prefix") or self._env_path("NPM_CONFIG_PREFIX")
        if prefix:
            out.append(prefix / "lib" / "node_modules")
        out += [
            Path("/usr/local/lib/node_modules"),
            Path("/opt/homebrew/lib/node_modules"),
            Path("/usr/lib/node_modules"),
        ]
        out += sorted((self.home / ".nvm" / "versions" / "node").glob("*/lib/node_modules"))[
            -_MAX_GLOB:
        ]
        appdata = self._env_path("APPDATA")
        if appdata:
            out.append(appdata / "npm" / "node_modules")
        node_path = self.env.get("NODE_PATH")
        if node_path:
            out += [Path(p) for p in node_path.split(os.pathsep) if p]
        return out

    def bun_caches(self) -> list[Path]:
        install = self._env_path("BUN_INSTALL") or (self.home / ".bun")
        return [install / "install" / "cache"]

    def pnpm_dlx_caches(self) -> list[Path]:
        out = [
            self.home / ".cache" / "pnpm" / "dlx",
            self.home / "Library" / "Caches" / "pnpm" / "dlx",
        ]
        xdg = self._env_path("XDG_CACHE_HOME")
        if xdg:
            out.insert(0, xdg / "pnpm" / "dlx")
        local = self._env_path("LOCALAPPDATA")
        if local:
            out.append(local / "pnpm-cache" / "dlx")
        return out

    def uv_caches(self) -> list[Path]:
        out: list[Path] = []
        explicit = self._env_path("UV_CACHE_DIR")
        if explicit:
            out.append(explicit)
        xdg = self._env_path("XDG_CACHE_HOME")
        if xdg:
            out.append(xdg / "uv")
        out += [self.home / ".cache" / "uv", self.home / "Library" / "Caches" / "uv"]
        local = self._env_path("LOCALAPPDATA")
        if local:
            out.append(local / "uv" / "cache")
        return out

    def uv_tool_dirs(self) -> list[Path]:
        explicit = self._env_path("UV_TOOL_DIR")
        out = [explicit] if explicit else []
        xdg = self._env_path("XDG_DATA_HOME")
        if xdg:
            out.append(xdg / "uv" / "tools")
        out.append(self.home / ".local" / "share" / "uv" / "tools")
        appdata = self._env_path("APPDATA")
        if appdata:
            out.append(appdata / "uv" / "data" / "tools")
        return out

    def pipx_venv_dirs(self) -> list[Path]:
        pipx_home = self._env_path("PIPX_HOME")
        out = [pipx_home / "venvs"] if pipx_home else []
        out += [
            self.home / ".local" / "pipx" / "venvs",
            self.home / "Library" / "Application Support" / "pipx" / "venvs",
        ]
        return out

    def virtualenvs(self, near: Path) -> list[Path]:
        out: list[Path] = []
        venv = self._env_path("VIRTUAL_ENV")
        if venv:
            out.append(venv)
        for d in [near, *list(near.parents)[:3]]:
            out += [d / ".venv", d / "venv"]
        return out


# ------------------------------------------------------------------------------- npm lookup


def _npm_name_version(spec: str) -> tuple[str, str | None]:
    m = _NPM_SPEC.match(spec)
    if not m:
        return spec, None
    ver = m.group("ver")
    return m.group("name"), (ver if ver and re.match(r"^v?\d", ver) else None)


def _read_package_json(d: Path) -> dict[str, str] | None:
    pj = d / "package.json"
    try:
        if not pj.is_file() or pj.stat().st_size > 1_000_000:
            return None
        data = json.loads(pj.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    out = {}
    for k in ("name", "version"):
        v = data.get(k)
        if isinstance(v, str):
            out[k] = v
    return out


def _npm_candidates(name: str, roots: SearchRoots, near: Path) -> list[tuple[Path, str]]:
    """Directories that may hold `<name>/package.json`, with the location label."""
    out: list[tuple[Path, str]] = []
    for cache in roots.npm_npx_caches():
        if cache.is_dir():
            for entry in sorted(cache.iterdir())[:_MAX_GLOB]:
                out.append((entry / "node_modules", "npx cache"))
    for cache in roots.pnpm_dlx_caches():
        if cache.is_dir():
            for entry in sorted(cache.iterdir())[:_MAX_GLOB]:
                out.append((entry / "node_modules", "pnpm dlx cache"))
    for d in [near, *list(near.parents)[:3], Path.cwd()]:
        out.append((d / "node_modules", "project node_modules"))
    for g in roots.npm_global_roots():
        out.append((g, "global node_modules"))
    return out


def _find_npm(
    name: str, version: str | None, roots: SearchRoots, near: Path
) -> tuple[Located | None, list[str]]:
    # every location kind consulted, whether or not it exists on this machine
    searched = [
        "npx cache",
        "pnpm dlx cache",
        "project node_modules",
        "global node_modules",
        "bun cache",
    ]
    best: tuple[float, Located] | None = None
    for base, label in _npm_candidates(name, roots, near):
        pkg_dir = base / name
        meta = _read_package_json(pkg_dir)
        if meta is None:
            continue
        found = Located(
            "npm", meta.get("name", name), meta.get("version"), pkg_dir, [pkg_dir], label, meta
        )
        if version and meta.get("version") == version.lstrip("v"):
            return found, searched
        try:
            mtime = pkg_dir.stat().st_mtime
        except OSError:
            mtime = 0.0
        if best is None or mtime > best[0]:
            best = (mtime, found)
    # bun keeps `<name>@<version>` directories
    for cache in roots.bun_caches():
        if not cache.is_dir():
            continue
        parent = cache / name.split("/")[0] if name.startswith("@") else cache
        leaf = name.split("/")[-1]
        try:
            entries = sorted(parent.iterdir())[:_MAX_GLOB]
        except OSError:
            continue
        for entry in entries:
            if not entry.name.startswith(leaf + "@"):
                continue
            meta = _read_package_json(entry)
            if meta is None:
                continue
            found = Located(
                "npm",
                meta.get("name", name),
                meta.get("version"),
                entry,
                [entry],
                "bun cache",
                meta,
            )
            if version and meta.get("version") == version.lstrip("v"):
                return found, searched
            if best is None:
                best = (0.0, found)
    if best is not None:
        loc = best[1]
        if version and loc.version != version.lstrip("v"):
            loc.located_by += f" (version {loc.version}, config asks for {version})"
        return loc, searched
    return None, searched


# ------------------------------------------------------------------------------- pypi lookup


def _norm_dist(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _py_name_version(spec: str) -> tuple[str, str | None]:
    m = _PY_SPEC.match(spec)
    if not m:
        return spec, None
    name = re.sub(r"\[.*\]$", "", m.group("name"))
    sp = m.group("spec") or ""
    vm = re.match(r"^(?:==|===|@)\s*v?([0-9][A-Za-z0-9.+\-]*)$", sp)
    return name, (vm.group(1) if vm else None)


def _site_packages_dirs(roots: SearchRoots, near: Path) -> list[tuple[Path, str]]:
    out: list[tuple[Path, str]] = []

    def add_venv(venv: Path, label: str) -> None:
        for sp in sorted(venv.glob("lib/python*/site-packages"))[:8]:
            out.append((sp, label))
        win = venv / "Lib" / "site-packages"
        if win.is_dir():
            out.append((win, label))

    for cache in roots.uv_caches():
        if not cache.is_dir():
            continue
        for arch in sorted(cache.glob("archive-v*"))[:4]:
            try:
                entries = sorted(arch.iterdir())[:_MAX_GLOB]
            except OSError:
                continue
            for entry in entries:
                add_venv(entry, "uv cache")
    for tools in roots.uv_tool_dirs():
        if tools.is_dir():
            for entry in sorted(tools.iterdir())[:_MAX_GLOB]:
                add_venv(entry, "uv tools")
    for venvs in roots.pipx_venv_dirs():
        if venvs.is_dir():
            for entry in sorted(venvs.iterdir())[:_MAX_GLOB]:
                add_venv(entry, "pipx")
    for venv in roots.virtualenvs(near):
        if venv.is_dir():
            add_venv(venv, "virtualenv")
    return out


def _dist_members(site: Path, info: Path) -> list[Path]:
    """Top-level packages/modules a dist-info installs, from top_level.txt or RECORD."""
    names: set[str] = set()
    tl = info / "top_level.txt"
    try:
        if tl.is_file():
            names |= {
                ln.strip() for ln in tl.read_text(encoding="utf-8").splitlines() if ln.strip()
            }
        rec = info / "RECORD"
        if not names and rec.is_file():
            for ln in rec.read_text(encoding="utf-8", errors="replace").splitlines()[:20000]:
                first = ln.split(",", 1)[0].split("/", 1)[0]
                if (
                    first
                    and not first.endswith((".dist-info", ".pth"))
                    and not first.startswith(("..", "__"))
                ):
                    names.add(first.removesuffix(".py"))
    except OSError:
        pass
    members: list[Path] = []
    for n in sorted(names):
        for cand in (site / n, site / f"{n}.py"):
            if cand.exists():
                members.append(cand)
                break
    return members


def _find_pypi(
    name: str, version: str | None, roots: SearchRoots, near: Path
) -> tuple[Located | None, list[str]]:
    searched = ["uv cache", "uv tools", "pipx", "virtualenv"]
    want = _norm_dist(name)
    best: Located | None = None
    for site, label in _site_packages_dirs(roots, near):
        try:
            infos = [p for p in site.iterdir() if p.name.endswith(".dist-info")]
        except OSError:
            continue
        for info in infos:
            m = re.match(r"^(?P<dist>.+?)-(?P<ver>[0-9][^-]*)\.dist-info$", info.name)
            if not m or _norm_dist(m.group("dist")) != want:
                continue
            members = _dist_members(site, info) or [site]
            found = Located("pypi", m.group("dist"), m.group("ver"), site, members, label)
            if version and m.group("ver") == version:
                return found, searched
            if best is None:
                best = found
    if best is not None and version and best.version != version:
        best.located_by += f" (version {best.version}, config asks for {version})"
    return best, searched


# ------------------------------------------------------------------------------- scripts


def _project_root(entry: Path) -> Path:
    """The package directory of a script: its own directory, or the nearest ancestor (at most two
    levels up, so `dist/index.js` and `src/pkg/server.py` work) that holds a project marker. Walking
    further would risk reading an unrelated repository that happens to contain the script."""
    d = entry.parent
    for cand in [d, *list(d.parents)[:2]]:
        if any((cand / m).is_file() for m in _PROJECT_MARKERS):
            return cand
    return d


def _resolve_script(arg: str, config_dir: Path) -> Path | None:
    p = Path(os.path.expanduser(arg))
    for base in (config_dir, Path.cwd()):
        cand = p if p.is_absolute() else base / p
        try:
            if cand.is_file():
                return cand.resolve()
        except OSError:
            continue
    return None


def _script_entry(server: ServerConfig) -> tuple[str, str] | None:
    """Return (script_arg, launcher_label) for `node x.js`, `python x.py`, `uv run x.py` and
    a config whose `command` is itself a script path."""
    if not server.command:
        return None
    cmd = basename(server.command).removesuffix(".exe")
    args = server.arg_values
    if server.command.endswith(SCRIPT_SUFFIXES):
        return server.command, "script path"
    base = re.sub(r"\d+(?:\.\d+)*$", "", cmd) if cmd.startswith("python") else cmd
    if base in SCRIPT_INTERPRETERS:
        for a in args:
            if a.startswith("-"):
                if a in ("-m", "-c", "-e", "--eval", "-p"):
                    return None
                continue
            if a.endswith(SCRIPT_SUFFIXES):
                return a, f"{cmd} script"
            return None
    if cmd == "uv" and "run" in args:
        i = args.index("run")
        for a in args[i + 1 :]:
            if a.startswith("-"):
                continue
            if a.endswith(SCRIPT_SUFFIXES):
                return a, "uv run script"
            return None
    return None


# ------------------------------------------------------------------------------- entry point


def locate(
    server: ServerConfig,
    *,
    config_dir: Path,
    overrides: dict[str, Path] | None = None,
    roots: SearchRoots | None = None,
) -> Located | UnlocatedPackage:
    roots = roots or SearchRoots()
    overrides = overrides or {}

    def missing(
        eco: str, spec: str, reason: str, searched: list[str] | None = None
    ) -> UnlocatedPackage:
        return UnlocatedPackage(
            server.name, server.source_file, server.json_path, eco, spec, reason, searched or []
        )

    ov = overrides.get(server.name)
    if ov is not None:
        if not ov.exists():
            return missing("path", str(ov), "--package-path does not exist")
        root = ov if ov.is_dir() else ov.parent
        return Located("path", server.name, None, root, [ov], "--package-path")

    if server.transport in ("http", "sse") and not server.command:
        return missing(
            "remote", server.url.value if server.url else "", "remote server; no local code to read"
        )
    if not server.command:
        return missing("unknown", "", "no command")

    found = package_spec(server)
    if found is not None:
        eco, spec, idx = found
        if not server.args[idx].literal:
            return missing(eco, spec, "package name is a runtime reference, not a literal")
        if spec.startswith((".", "/", "~")) or re.match(r"^[A-Za-z]:[\\/]", spec):
            p = _resolve_script(spec, config_dir)
            if p is None:
                p = (config_dir / os.path.expanduser(spec)).resolve()
                if not p.is_dir():
                    return missing(eco, spec, "local package path not found")
            root = p if p.is_dir() else _project_root(p)
            return Located("path", spec, None, root, [p], "config-relative path")
        if eco == "npm":
            name, version = _npm_name_version(spec)
            loc, searched = _find_npm(name, version, roots, config_dir)
            return loc or missing(eco, spec, "package not installed in any local cache", searched)
        name, version = _py_name_version(spec)
        loc, searched = _find_pypi(name, version, roots, config_dir)
        return loc or missing(eco, spec, "package not installed in any local environment", searched)

    cmd = basename(server.command).removesuffix(".exe")
    if cmd in CONTAINER_LAUNCHERS:
        return missing(
            "container", server.command_line, "container image; image contents are not read"
        )

    entry = _script_entry(server)
    if entry is not None:
        arg, label = entry
        p = _resolve_script(arg, config_dir)
        if p is None:
            return missing(
                "path",
                arg,
                "script path not found (relative to the config file or the current directory)",
            )
        root = _project_root(p)
        meta = _read_package_json(root) or {}
        return Located(
            "path", meta.get("name") or p.name, meta.get("version"), root, [root], label, meta
        )
    return missing(
        "unknown", server.command_line, "launcher not recognised; use --package-path NAME=DIR"
    )
