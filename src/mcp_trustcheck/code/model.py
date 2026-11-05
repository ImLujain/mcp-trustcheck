"""Capability manifests: what the code behind a configured server can do (docs/design.md §8).

A manifest is derived from package source already present on disk. Nothing is executed and
nothing is fetched. Every entry is a static observation ("this handler reaches `subprocess.run`"),
never a claim that the behaviour is malicious.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from mcp_trustcheck.redaction import Redactor

CAPABILITY_CLASSES: tuple[str, ...] = (
    "exec",
    "fs_read",
    "fs_write",
    "fs_delete",
    "network",
    "env",
    "dynamic_code",
    "native",
)

PHRASES: dict[str, str] = {
    "exec": "run programs",
    "fs_read": "read files",
    "fs_write": "write files",
    "fs_delete": "delete files",
    "network": "reach the network",
    "env": "read environment variables",
    "dynamic_code": "load code at runtime",
    "native": "load native code",
}

SIDE_EFFECT_CLASSES = frozenset({"exec", "fs_write", "fs_delete"})

# Dynamic-code callees that merely resolve a module name. They are recorded in the manifest but do
# not by themselves count as "can fetch and run code" (CFG-019).
WEAK_DYNAMIC_CALLEES = frozenset(
    {"import()", "require()", "importlib.import_module", "__import__", "importlib.reload"}
)

SNIPPET_MAX = 200


@dataclass(frozen=True)
class Sink:
    """One statically observed capability use."""

    cls: str  # one of CAPABILITY_CLASSES
    file: str  # path relative to the package root, POSIX separators
    line: int
    callee: str  # e.g. "subprocess.run", "child_process.execSync", "fetch"
    detail: str | None = None  # literal host, env name, path or open() mode when visible
    snippet: str = ""  # the source line, trimmed and redacted

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "class": self.cls,
            "file": self.file,
            "line": self.line,
            "callee": self.callee,
        }
        if self.detail:
            d["detail"] = self.detail
        if self.snippet:
            d["snippet"] = self.snippet
        return d


@dataclass
class ToolCapabilities:
    """Capabilities reachable from the handler of one tool."""

    name: str
    handler: str  # "file:line" of the handler, or "" when only declared
    sinks: list[Sink] = field(default_factory=list)
    depth: int = 0  # how many call levels were followed from the handler

    @property
    def classes(self) -> set[str]:
        return {s.cls for s in self.sinks}

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "handler": self.handler,
            "classes": sorted(self.classes),
            "sinks": [s.to_dict() for s in self.sinks],
        }


@dataclass
class PackageManifest:
    server: str
    source_file: str
    json_path: str
    ecosystem: str  # "npm" | "pypi" | "path"
    name: str
    version: str | None
    root: str  # display path of the code that was read
    located_by: str  # which search location produced it
    language: str  # "python" | "javascript" | "mixed" | "none"
    files_scanned: int
    bytes_scanned: int
    digest: str  # sha256 over (relative path, sha256(content)) of every file read
    attribution: str  # "ast" | "lexical" | "none"
    sinks: list[Sink] = field(default_factory=list)
    tools: dict[str, ToolCapabilities] = field(default_factory=dict)
    declared_tools: list[str] = field(default_factory=list)
    install_hooks: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def classes(self) -> set[str]:
        return {s.cls for s in self.sinks}

    def details(self, cls: str) -> list[str]:
        return sorted({s.detail for s in self.sinks if s.cls == cls and s.detail})

    @property
    def hosts(self) -> list[str]:
        return self.details("network")

    @property
    def env_names(self) -> list[str]:
        return self.details("env")

    def redact(self, redactor: Redactor) -> None:
        """Scrub every value the scan classified as sensitive out of snippets and details."""

        def fix(s: Sink) -> Sink:
            return Sink(
                s.cls,
                s.file,
                s.line,
                s.callee,
                redactor.scrub(s.detail) if s.detail else None,
                redactor.snippet(s.snippet)[:SNIPPET_MAX] if s.snippet else "",
            )

        self.sinks = [fix(s) for s in self.sinks]
        for tc in self.tools.values():
            tc.sinks = [fix(s) for s in tc.sinks]
        self.install_hooks = {k: redactor.snippet(v) for k, v in self.install_hooks.items()}

    def summary(self) -> str:
        """One plain-language sentence: what this package's code can do."""
        parts: list[str] = []
        for cls in CAPABILITY_CLASSES:
            if cls not in self.classes:
                continue
            phrase = PHRASES[cls]
            det = self.details(cls)
            if cls in ("network", "env") and det:
                phrase += " (" + ", ".join(det[:4]) + (", …" if len(det) > 4 else "") + ")"
            parts.append(phrase)
        if not parts:
            return "no capability sinks found in the code that was read"
        return "can " + "; ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": "analysed",
            "server": self.server,
            "source_file": self.source_file,
            "json_path": self.json_path,
            "ecosystem": self.ecosystem,
            "name": self.name,
            "version": self.version,
            "root": self.root,
            "located_by": self.located_by,
            "language": self.language,
            "files_scanned": self.files_scanned,
            "bytes_scanned": self.bytes_scanned,
            "digest": self.digest,
            "attribution": self.attribution,
            "classes": sorted(self.classes),
            "hosts": self.hosts,
            "env": self.env_names,
            "summary": self.summary(),
            "sinks": [s.to_dict() for s in self.sinks],
            "tools": [self.tools[k].to_dict() for k in sorted(self.tools)],
            "declared_tools": sorted(self.declared_tools),
            "install_hooks": dict(sorted(self.install_hooks.items())),
            "notes": list(self.notes),
        }


@dataclass
class UnlocatedPackage:
    server: str
    source_file: str
    json_path: str
    ecosystem: str  # "npm" | "pypi" | "path" | "container" | "remote" | "unknown"
    spec: str
    reason: str
    searched: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": "not_located",
            "server": self.server,
            "source_file": self.source_file,
            "json_path": self.json_path,
            "ecosystem": self.ecosystem,
            "spec": self.spec,
            "reason": self.reason,
            "searched": list(self.searched),
        }
