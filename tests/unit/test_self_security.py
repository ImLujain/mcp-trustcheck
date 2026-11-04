"""The tool must never execute commands, open sockets, or reach the network (design.md §6).

This test is a static guard: it fails if any forbidden module is imported anywhere in src/.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "mcp_trustcheck"

FORBIDDEN_MODULES = {
    "subprocess",
    "socket",
    "urllib",
    "urllib.request",
    "urllib.error",
    "urllib.robotparser",
    "http",
    "http.client",
    "http.server",
    "requests",
    "httpx",
    "aiohttp",
    "asyncio",
    "pty",
    "pexpect",
    "ssl",
    "ftplib",
    "smtplib",
    "telnetlib",
    "xmlrpc",
    "multiprocessing",
}
# Pure parsers with no I/O. Anything else under a forbidden root stays forbidden.
ALLOWED_MODULES = {"urllib.parse"}
FORBIDDEN_CALLS = {("os", "system"), ("os", "popen"), ("os", "exec"), ("os", "spawn")}


def _imports(tree: ast.AST):  # type: ignore[no-untyped-def]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            yield node.module


def test_no_forbidden_imports() -> None:
    offenders = []
    for py in SRC.rglob("*.py"):
        tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        for mod in _imports(tree):
            if mod in ALLOWED_MODULES:
                continue
            root = mod.split(".")[0]
            if mod in FORBIDDEN_MODULES or root in FORBIDDEN_MODULES:
                offenders.append(f"{py.relative_to(SRC)}: import {mod}")
    assert not offenders, "\n".join(offenders)


def test_no_builtin_eval_or_exec() -> None:
    offenders = []
    for py in SRC.rglob("*.py"):
        tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = node.func
                if isinstance(fn, ast.Name) and fn.id in {"eval", "exec", "compile", "__import__"}:
                    offenders.append(f"{py.relative_to(SRC)}:{node.lineno}: {fn.id}()")
                if (
                    isinstance(fn, ast.Attribute)
                    and isinstance(fn.value, ast.Name)
                    and any(fn.value.id == m and fn.attr.startswith(a) for m, a in FORBIDDEN_CALLS)
                ):
                    offenders.append(
                        f"{py.relative_to(SRC)}:{node.lineno}: {fn.value.id}.{fn.attr}()"
                    )
    assert not offenders, "\n".join(offenders)
