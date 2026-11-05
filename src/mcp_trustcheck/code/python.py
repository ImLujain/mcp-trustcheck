"""Python source analyser: capability sinks and tool-handler attribution via the `ast` module.

Everything is resolved from the module's own imports (`import subprocess as sp` makes `sp.run` a
`subprocess.run`), so the tables below name real library entry points, not vocabulary. Handlers are
attributed from the MCP Python SDK's registration idioms: `@mcp.tool()` (FastMCP), `mcp.add_tool(fn)`,
and the low-level `@server.call_tool()` dispatcher whose body branches on the tool name.
"""

from __future__ import annotations

import ast
import re

from mcp_trustcheck.code.common import FunctionInfo, ModuleResult, host_of_literal, safe_snippet
from mcp_trustcheck.code.model import Sink

EXEC_CALLEES = frozenset(
    {
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
        "os.system",
        "os.popen",
        "os.execv",
        "os.execve",
        "os.execvp",
        "os.execvpe",
        "os.execl",
        "os.execle",
        "os.execlp",
        "os.execlpe",
        "os.spawnl",
        "os.spawnle",
        "os.spawnlp",
        "os.spawnlpe",
        "os.spawnv",
        "os.spawnve",
        "os.spawnvp",
        "os.spawnvpe",
        "os.startfile",
        "os.posix_spawn",
        "os.posix_spawnp",
        "asyncio.create_subprocess_exec",
        "asyncio.create_subprocess_shell",
        "pty.spawn",
        "pexpect.spawn",
        "pexpect.run",
        "sh.Command",
        "plumbum.local",
        "invoke.run",
        "fabric.Connection",
    }
)
FS_DELETE_CALLEES = frozenset(
    {
        "os.remove",
        "os.unlink",
        "os.rmdir",
        "os.removedirs",
        "shutil.rmtree",
        "send2trash.send2trash",
    }
)
FS_WRITE_CALLEES = frozenset(
    {
        "os.makedirs",
        "os.mkdir",
        "os.rename",
        "os.renames",
        "os.replace",
        "os.chmod",
        "os.chown",
        "os.symlink",
        "os.link",
        "os.truncate",
        "shutil.copy",
        "shutil.copy2",
        "shutil.copyfile",
        "shutil.copytree",
        "shutil.move",
        "shutil.chown",
        "tempfile.mkstemp",
        "tempfile.mkdtemp",
        "tempfile.NamedTemporaryFile",
        "tempfile.TemporaryDirectory",
    }
)
FS_READ_CALLEES = frozenset(
    {"os.listdir", "os.scandir", "os.walk", "glob.glob", "glob.iglob", "os.stat", "os.path.exists"}
)
# pathlib-style method names, counted only when pathlib/Path is imported in the module.
PATH_WRITE_METHODS = frozenset(
    {"write_text", "write_bytes", "touch", "mkdir", "rename", "replace", "symlink_to", "chmod"}
)
PATH_DELETE_METHODS = frozenset({"unlink", "rmdir"})
PATH_READ_METHODS = frozenset(
    {"read_text", "read_bytes", "iterdir", "glob", "rglob", "stat", "exists"}
)
OPEN_CALLEES = frozenset(
    {
        "open",
        "io.open",
        "aiofiles.open",
        "codecs.open",
        "gzip.open",
        "tarfile.open",
        "zipfile.ZipFile",
    }
)
NETWORK_PREFIXES = (
    "urllib.request",
    "urllib3",
    "http.client",
    "httpx",
    "httpcore",
    "requests",
    "aiohttp",
    "socket",
    "ssl",
    "websockets",
    "websocket",
    "smtplib",
    "ftplib",
    "paramiko",
    "asyncssh",
    "telnetlib",
    "xmlrpc.client",
    "imaplib",
    "poplib",
    "boto3",
    "botocore",
    "openai",
    "anthropic",
    "google.cloud",
    "google.auth",
    "googleapiclient",
    "grpc",
    "pymongo",
    "motor",
    "psycopg",
    "psycopg2",
    "asyncpg",
    "redis",
    "aioredis",
    "pika",
    "kafka",
    "twilio",
    "slack_sdk",
    "github",
    "gitlab",
    "kubernetes",
    "docker",
    "mcp.client",
    "pymysql",
    "mysql.connector",
    "elasticsearch",
    "ldap3",
)
ENV_CALLEES = frozenset(
    {
        "os.getenv",
        "os.environ.get",
        "os.environ.setdefault",
        "os.environ.copy",
        "dotenv.load_dotenv",
        "dotenv.dotenv_values",
        "environ.get",
    }
)
DYNAMIC_CALLEES = frozenset(
    {
        "eval",
        "exec",
        "compile",
        "importlib.import_module",
        "__import__",
        "importlib.reload",
        "runpy.run_path",
        "runpy.run_module",
        "pickle.load",
        "pickle.loads",
        "marshal.load",
        "marshal.loads",
        "dill.load",
        "dill.loads",
        "yaml.load",
        "yaml.unsafe_load",
        "types.FunctionType",
    }
)
NATIVE_PREFIXES = ("ctypes", "cffi")

_TOOL_CLASS_RE = re.compile(r"(?:^|\.)Tool$")
_WRITE_MODE_RE = re.compile(r"[wax+]")


def _qualname(node: ast.AST, imports: dict[str, str]) -> str | None:
    """`sp.run` -> "subprocess.run" given `import subprocess as sp`; `self.x` stays "self.x"."""
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        base = imports.get(cur.id, cur.id)
        return ".".join([base, *reversed(parts)])
    if isinstance(cur, ast.Call):  # chained call such as Path(x).write_text(...)
        inner = _qualname(cur.func, imports)
        return ".".join([inner or "()", *reversed(parts)]) if parts else inner
    return None


def _str_arg(call: ast.Call, index: int, kw: str | None = None) -> str | None:
    if len(call.args) > index:
        arg = call.args[index]
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return arg.value
    if kw:
        for k in call.keywords:
            if k.arg == kw and isinstance(k.value, ast.Constant) and isinstance(k.value.value, str):
                return str(k.value.value)
    return None


def _literal_url_host(call: ast.Call) -> str | None:
    for a in [*call.args, *[k.value for k in call.keywords]]:
        if isinstance(a, ast.Constant) and isinstance(a.value, str):
            h = host_of_literal(a.value)
            if h:
                return h
        if isinstance(a, ast.JoinedStr):
            for v in a.values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    h = host_of_literal(v.value)
                    if h:
                        return h
    return None


class _Analyser(ast.NodeVisitor):
    def __init__(self, file: str, lines: list[str]) -> None:
        self.file = file
        self.lines = lines
        self.imports: dict[str, str] = {}
        self.module_aliases: dict[str, str] = {}  # alias -> last segment of a local module
        self.uses_pathlib = False
        self.res = ModuleResult(file=file, attribution="ast")
        self.stack: list[FunctionInfo] = []
        self.class_stack: list[str] = []

    # -- helpers ---------------------------------------------------------------------------
    def _line(self, node: ast.AST) -> str:
        n = getattr(node, "lineno", 0)
        return safe_snippet(self.lines[n - 1]) if 0 < n <= len(self.lines) else ""

    def _sink(self, node: ast.AST, cls: str, callee: str, detail: str | None = None) -> None:
        s = Sink(cls, self.file, getattr(node, "lineno", 0), callee, detail, self._line(node))
        self.res.sinks.append(s)
        if self.stack:
            self.stack[-1].sinks.append(s)

    def _call(self, name: str) -> None:
        if self.stack:
            self.stack[-1].calls.add(name)

    def _push(self, key: str, name: str, line: int) -> FunctionInfo:
        info = self.res.functions.get(key)
        if info is None:
            info = FunctionInfo(key=key, name=name, file=self.file, line=line)
            self.res.functions[key] = info
        self.stack.append(info)
        return info

    def _pop(self) -> None:
        self.stack.pop()

    # -- imports ---------------------------------------------------------------------------
    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            self.imports[a.asname or a.name.split(".")[0]] = (
                a.name if a.asname else a.name.split(".")[0]
            )
            if a.name.startswith(("pathlib",)):
                self.uses_pathlib = True
            if any(a.name == p or a.name.startswith(p + ".") for p in NETWORK_PREFIXES):
                self._sink(node, "network", f"import {a.name}", None)
            if a.name.split(".")[0] in NATIVE_PREFIXES:
                self._sink(node, "native", f"import {a.name}")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = node.module or ""
        for a in node.names:
            local = a.asname or a.name
            if node.level:  # relative import: a module of this package
                self.module_aliases[local] = a.name
                self.imports[local] = a.name
            else:
                self.imports[local] = f"{mod}.{a.name}" if mod else a.name
        if mod.startswith("pathlib") or any(a.name == "Path" for a in node.names):
            self.uses_pathlib = True
        if not node.level and any(mod == p or mod.startswith(p + ".") for p in NETWORK_PREFIXES):
            self._sink(node, "network", f"from {mod} import …")
        if not node.level and mod.split(".")[0] in NATIVE_PREFIXES:
            self._sink(node, "native", f"from {mod} import …")
        self.generic_visit(node)

    # -- definitions -----------------------------------------------------------------------
    def _decorator_tool_name(
        self, fn: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> tuple[str | None, bool, bool]:
        """Return (tool name, is_dispatcher, is_list_tools)."""
        for dec in fn.decorator_list:
            target = dec.func if isinstance(dec, ast.Call) else dec
            q = _qualname(target, self.imports) or ""
            last = q.rsplit(".", 1)[-1]
            if last == "tool":
                name = _str_arg(dec, 0, "name") if isinstance(dec, ast.Call) else None
                return name or fn.name, False, False
            if last == "call_tool":
                return None, True, False
            if last == "list_tools":
                return None, False, True
        return None, False, False

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        qual = ".".join([*self.class_stack, node.name])
        key = f"{self.file}::{qual}"
        tool, dispatcher, _ = self._decorator_tool_name(node)
        info = self._push(key, node.name, node.lineno)
        if tool:
            self.res.tools[tool] = key
        if dispatcher:
            self._visit_dispatcher_body(node.body)
        else:
            for stmt in node.body:
                self.visit(stmt)
        self._pop()
        _ = info

    visit_FunctionDef = _visit_function  # noqa: N815 - ast.NodeVisitor naming
    visit_AsyncFunctionDef = _visit_function  # noqa: N815

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.class_stack.append(node.name)
        for stmt in node.body:
            self.visit(stmt)
        self.class_stack.pop()

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self.generic_visit(node)

    # -- dispatcher: `@server.call_tool()` bodies branch on the tool name ----------------------
    @staticmethod
    def _names_from_test(test: ast.expr) -> list[str]:
        names: list[str] = []
        if isinstance(test, ast.Compare) and len(test.ops) == 1:
            comp = test.comparators[0]
            if (
                isinstance(test.ops[0], ast.Eq)
                and isinstance(comp, ast.Constant)
                and isinstance(comp.value, str)
            ):
                names.append(comp.value)
            elif isinstance(test.ops[0], ast.In) and isinstance(
                comp, (ast.Tuple, ast.List, ast.Set)
            ):
                names += [
                    e.value
                    for e in comp.elts
                    if isinstance(e, ast.Constant) and isinstance(e.value, str)
                ]
        elif isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or):
            for v in test.values:
                names += _Analyser._names_from_test(v)
        return names

    def _visit_dispatcher_body(self, body: list[ast.stmt]) -> None:
        for stmt in body:
            if isinstance(stmt, ast.If):
                self._visit_if_chain(stmt)
            elif isinstance(stmt, ast.Match):
                for case in stmt.cases:
                    names = self._match_names(case.pattern)
                    self._visit_branch(names, case.body, stmt.lineno)
            else:
                self.visit(stmt)

    @staticmethod
    def _match_names(pat: ast.pattern) -> list[str]:
        if (
            isinstance(pat, ast.MatchValue)
            and isinstance(pat.value, ast.Constant)
            and isinstance(pat.value.value, str)
        ):
            return [pat.value.value]
        if isinstance(pat, ast.MatchOr):
            out: list[str] = []
            for p in pat.patterns:
                out += _Analyser._match_names(p)
            return out
        return []

    def _visit_if_chain(self, node: ast.If) -> None:
        names = self._names_from_test(node.test)
        self._visit_branch(names, node.body, node.lineno)
        if len(node.orelse) == 1 and isinstance(node.orelse[0], ast.If):
            self._visit_if_chain(node.orelse[0])
        else:
            for stmt in node.orelse:
                self.visit(stmt)

    def _visit_branch(self, names: list[str], body: list[ast.stmt], line: int) -> None:
        if not names:
            for stmt in body:
                self.visit(stmt)
            return
        key = f"{self.file}::tool:{names[0]}"
        self._push(key, f"tool:{names[0]}", line)
        for n in names:
            self.res.tools.setdefault(n, key)
        for stmt in body:
            self.visit(stmt)
        self._pop()

    # -- expressions -----------------------------------------------------------------------
    def visit_Subscript(self, node: ast.Subscript) -> None:
        q = _qualname(node.value, self.imports)
        if q in ("os.environ", "environ"):
            key = (
                node.slice.value
                if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str)
                else None
            )
            self._sink(node, "env", "os.environ[]", key)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        # `handlers = {"tool_a": handle_a, ...}` dispatch tables
        if isinstance(node.value, ast.Dict):
            for k, v in zip(node.value.keys, node.value.values, strict=True):
                if (
                    isinstance(k, ast.Constant)
                    and isinstance(k.value, str)
                    and isinstance(v, ast.Name)
                ):
                    self.res.tools.setdefault(k.value, v.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        q = _qualname(node.func, self.imports)
        if q:
            self._classify(q, node)
            self._record_call(q, node)
        self.generic_visit(node)

    def _record_call(self, q: str, node: ast.Call) -> None:
        last = q.rsplit(".", 1)[-1]
        if last == "add_tool" and node.args and isinstance(node.args[0], ast.Name):
            name = _str_arg(node, 1, "name") or node.args[0].id
            self.res.tools.setdefault(name, node.args[0].id)
        if _TOOL_CLASS_RE.search(q):
            declared = _str_arg(node, 0, "name")
            if declared:
                self.res.declared.add(declared)
        if isinstance(node.func, ast.Name):
            self._call(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            base = node.func.value
            if isinstance(base, ast.Name):
                if base.id in ("self", "cls"):
                    self._call(node.func.attr)
                elif base.id in self.module_aliases:
                    self._call(f"{self.module_aliases[base.id]}|{node.func.attr}")
                else:
                    self._call(
                        f"{self.imports.get(base.id, base.id).rsplit('.', 1)[-1]}|{node.func.attr}"
                    )

    def _classify(self, q: str, node: ast.Call) -> None:
        last = q.rsplit(".", 1)[-1]
        if q in EXEC_CALLEES:
            self._sink(node, "exec", q, _str_arg(node, 0))
        elif q in FS_DELETE_CALLEES:
            self._sink(node, "fs_delete", q, _str_arg(node, 0))
        elif q in FS_WRITE_CALLEES:
            self._sink(node, "fs_write", q, _str_arg(node, 0))
        elif q in FS_READ_CALLEES:
            self._sink(node, "fs_read", q, _str_arg(node, 0))
        elif q in OPEN_CALLEES:
            mode = _str_arg(node, 1, "mode") or "r"
            cls = "fs_write" if _WRITE_MODE_RE.search(mode) else "fs_read"
            self._sink(node, cls, q, f"mode={mode}" if mode != "r" else _str_arg(node, 0))
        elif self.uses_pathlib and last in PATH_WRITE_METHODS and "." in q:
            self._sink(node, "fs_write", f"Path.{last}")
        elif self.uses_pathlib and last in PATH_DELETE_METHODS and "." in q:
            self._sink(node, "fs_delete", f"Path.{last}")
        elif self.uses_pathlib and last in PATH_READ_METHODS and "." in q:
            self._sink(node, "fs_read", f"Path.{last}")
        elif q in ENV_CALLEES:
            self._sink(node, "env", q, _str_arg(node, 0, "key"))
        elif q in DYNAMIC_CALLEES:
            self._sink(node, "dynamic_code", q, _str_arg(node, 0))
        elif any(q == p or q.startswith(p + ".") for p in NETWORK_PREFIXES):
            self._sink(node, "network", q, _literal_url_host(node))
        elif any(q == p or q.startswith(p + ".") for p in NATIVE_PREFIXES):
            self._sink(node, "native", q)
        elif last in (
            "get",
            "post",
            "put",
            "delete",
            "patch",
            "request",
            "stream",
            "send",
        ) and _literal_url_host(node):
            # a client object whose origin we could not resolve, called with a literal URL
            self._sink(node, "network", q, _literal_url_host(node))


_LEXICAL_SINKS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "exec",
        re.compile(r"\b(?:subprocess\.\w+|os\.system|os\.popen|os\.exec\w*|os\.spawn\w*)\s*\("),
    ),
    ("fs_delete", re.compile(r"\b(?:os\.remove|os\.unlink|shutil\.rmtree)\s*\(")),
    ("fs_write", re.compile(r"\bopen\s*\([^)]*[\"'][wax]")),
    ("network", re.compile(r"\b(?:requests|httpx|urllib\.request|aiohttp|socket)\.\w+\s*\(")),
    ("env", re.compile(r"\bos\.(?:environ|getenv)\b")),
    ("dynamic_code", re.compile(r"(?<![\w.])(?:eval|exec)\s*\(")),
)


def analyse_python(file: str, text: str) -> ModuleResult:
    lines = text.splitlines()
    try:
        tree = ast.parse(text, filename=file)
    except (SyntaxError, ValueError, RecursionError) as exc:
        res = ModuleResult(file=file, attribution="lexical")
        res.notes.append(
            f"{file}: not parseable as Python ({type(exc).__name__}); lexical scan only"
        )
        for i, ln in enumerate(lines, 1):
            for cls, rx in _LEXICAL_SINKS:
                m = rx.search(ln)
                if m:
                    res.sinks.append(
                        Sink(cls, file, i, m.group(0).rstrip("( "), None, safe_snippet(ln))
                    )
        return res
    an = _Analyser(file, lines)
    an.visit(tree)
    return an.res
