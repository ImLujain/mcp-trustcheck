"""JavaScript / TypeScript analyser without a parser: lexical, import-aware, range-based.

The standard library has no JavaScript parser, so this module masks comments, strings, template
literals and regex literals (keeping offsets intact), then matches sinks only when the file really
binds the relevant module (`const { execSync } = require("node:child_process")`, `import * as fs
from "fs/promises"`). Handlers are attributed by range: the arguments of `server.tool("name", …)`,
the `case "name":` arms of a `switch (name)` in a `tools/call` handler, or an
`if (name === "name") {…}` block. Results are reported as *lexical* attribution: a reviewer should
treat them as medium confidence.
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass

from mcp_trustcheck.code.common import FunctionInfo, ModuleResult, hosts_in, safe_snippet
from mcp_trustcheck.code.model import Sink

CHILD_PROCESS_MODULES = frozenset(
    {
        "child_process",
        "node:child_process",
        "execa",
        "shelljs",
        "zx",
        "cross-spawn",
        "node-pty",
        "@lydell/node-pty",
        "promisify-child-process",
        "tinyexec",
        "nano-spawn",
    }
)
CHILD_PROCESS_METHODS = frozenset(
    {
        "exec",
        "execSync",
        "execFile",
        "execFileSync",
        "spawn",
        "spawnSync",
        "fork",
        "execa",
        "execaSync",
        "execaCommand",
        "execaCommandSync",
        "$",
        "x",
    }
)
FS_MODULES = frozenset(
    {
        "fs",
        "node:fs",
        "fs/promises",
        "node:fs/promises",
        "fs-extra",
        "graceful-fs",
        "fs-jetpack",
        "original-fs",
        "memfs",
    }
)
FS_WRITE = frozenset(
    {
        "writeFile",
        "writeFileSync",
        "appendFile",
        "appendFileSync",
        "mkdir",
        "mkdirSync",
        "mkdirp",
        "rename",
        "renameSync",
        "copyFile",
        "copyFileSync",
        "cp",
        "cpSync",
        "createWriteStream",
        "chmod",
        "chmodSync",
        "chown",
        "chownSync",
        "symlink",
        "symlinkSync",
        "truncate",
        "truncateSync",
        "writeJson",
        "writeJsonSync",
        "outputFile",
        "outputFileSync",
        "outputJson",
        "ensureDir",
        "ensureFile",
        "copy",
        "copySync",
        "move",
        "moveSync",
        "utimes",
        "writeFileAsync",
        "write",
    }
)
FS_DELETE = frozenset(
    {
        "unlink",
        "unlinkSync",
        "rm",
        "rmSync",
        "rmdir",
        "rmdirSync",
        "remove",
        "removeSync",
        "emptyDir",
        "emptyDirSync",
    }
)
FS_READ = frozenset(
    {
        "readFile",
        "readFileSync",
        "readdir",
        "readdirSync",
        "createReadStream",
        "stat",
        "statSync",
        "lstat",
        "lstatSync",
        "existsSync",
        "access",
        "accessSync",
        "readJson",
        "readJsonSync",
        "readFileAsync",
        "opendir",
        "opendirSync",
        "realpath",
        "realpathSync",
        "readlink",
        "readlinkSync",
        "pathExists",
        "pathExistsSync",
        "watch",
        "watchFile",
    }
)
NETWORK_MODULES = frozenset(
    {
        "http",
        "node:http",
        "https",
        "node:https",
        "http2",
        "node:http2",
        "net",
        "node:net",
        "tls",
        "node:tls",
        "dgram",
        "node:dgram",
        "dns",
        "node:dns",
        "axios",
        "node-fetch",
        "undici",
        "got",
        "ky",
        "superagent",
        "request",
        "needle",
        "phin",
        "bent",
        "cross-fetch",
        "isomorphic-fetch",
        "ws",
        "socket.io-client",
        "socket.io",
        "@octokit/rest",
        "@octokit/core",
        "octokit",
        "openai",
        "@anthropic-ai/sdk",
        "@google/generative-ai",
        "googleapis",
        "@aws-sdk/client-s3",
        "aws-sdk",
        "@azure/identity",
        "pg",
        "mysql",
        "mysql2",
        "mongodb",
        "mongoose",
        "ioredis",
        "redis",
        "nodemailer",
        "@slack/web-api",
        "twilio",
        "@sendgrid/mail",
        "stripe",
        "@supabase/supabase-js",
        "firebase",
        "firebase-admin",
        "@modelcontextprotocol/sdk/client/index.js",
        "puppeteer",
        "puppeteer-core",
        "playwright",
        "playwright-core",
        "ssh2",
        "node-ssh",
        "nodemailer-smtp-transport",
        "amqplib",
        "kafkajs",
        "elasticsearch",
        "@elastic/elasticsearch",
        "ldapjs",
    }
)
NATIVE_MODULES = frozenset(
    {"ffi-napi", "koffi", "bindings", "node-gyp-build", "node-addon-api", "ref-napi"}
)
VM_MODULES = frozenset({"vm", "node:vm", "vm2", "isolated-vm"})
ENV_MODULES = frozenset(
    {"dotenv", "dotenv/config", "dotenv-flow", "dotenv-expand", "@dotenvx/dotenvx"}
)

_KEYWORDS = frozenset(
    [
        "if",
        "for",
        "while",
        "switch",
        "catch",
        "return",
        "function",
        "new",
        "typeof",
        "instanceof",
        "await",
        "yield",
        "delete",
        "void",
        "in",
        "of",
        "else",
        "do",
        "try",
        "throw",
        "class",
        "extends",
        "super",
        "import",
        "export",
        "default",
        "case",
        "break",
        "continue",
        "with",
        "let",
        "const",
        "var",
        "async",
        "static",
        "get",
        "set",
    ]
)

_DEF_RES = (
    re.compile(r"(?<![\w$.])(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\("),
    re.compile(
        r"(?<![\w$.])(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\b[^{]*|\([^)]*\)\s*(?::\s*[^=]+?)?\s*=>|[A-Za-z_$][\w$]*\s*=>)\s*"
    ),
    re.compile(
        r"^[ \t]*(?:public\s+|private\s+|protected\s+|static\s+|async\s+|override\s+)*([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*(?::\s*[^{;]+?)?\s*\{",
        re.M,
    ),
    re.compile(
        r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*:\s*(?:async\s*)?(?:function\b[^{]*|\([^)]*\)\s*=>)\s*"
    ),
)


@dataclass
class _Range:
    start: int
    end: int
    key: str
    name: str
    line: int
    is_tool: bool = False


class _Source:
    def __init__(self, file: str, text: str) -> None:
        self.file = file
        self.text = text
        self.masked, self.strings = _mask(text)
        self.lines = text.splitlines()
        self.line_starts = [0]
        for i, ch in enumerate(text):
            if ch == "\n":
                self.line_starts.append(i + 1)

    def line_of(self, pos: int) -> int:
        return bisect.bisect_right(self.line_starts, pos)

    def snippet(self, pos: int) -> str:
        n = self.line_of(pos)
        return safe_snippet(self.lines[n - 1]) if 0 < n <= len(self.lines) else ""

    def string_at(self, quote_pos: int) -> str:
        """Content of the string literal whose opening quote is at `quote_pos`."""
        for s, e in self.strings:
            if s == quote_pos:
                return self.text[s + 1 : e - 1]
        return ""

    def strings_in(self, start: int, end: int) -> list[str]:
        return [self.text[s + 1 : e - 1] for s, e in self.strings if s >= start and e <= end]

    def match_close(self, open_pos: int) -> int:
        """Index just past the bracket matching the one at `open_pos` in the masked text."""
        pairs = {"(": ")", "[": "]", "{": "}"}
        opener = self.masked[open_pos]
        closer = pairs[opener]
        depth = 0
        for i in range(open_pos, len(self.masked)):
            c = self.masked[i]
            if c == opener:
                depth += 1
            elif c == closer:
                depth -= 1
                if depth == 0:
                    return i + 1
        return len(self.masked)


def _mask(text: str) -> tuple[str, list[tuple[int, int]]]:
    """Blank out comments, string/template contents and regex literals; keep length and newlines."""
    out = list(text)
    strings: list[tuple[int, int]] = []
    i, n = 0, len(text)
    prev_sig = ""  # previous significant (non-space) char outside strings/comments

    def blank(a: int, b: int) -> None:
        for k in range(a, b):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = text[i]
        two = text[i : i + 2]
        if two == "//":
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
            continue
        if two == "/*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            blank(i, j)
            i = j
            continue
        if c in ("'", '"', "`"):
            j = i + 1
            while j < n:
                d = text[j]
                if d == "\\":
                    j += 2
                    continue
                if d == c:
                    break
                if c != "`" and d == "\n":
                    break
                j += 1
            j = min(j + 1, n)
            blank(i + 1, j - 1)
            strings.append((i, j))
            prev_sig = c
            i = j
            continue
        if c == "/" and (
            prev_sig == "" or prev_sig in "(,=:[!&|?{};+-*%<>~^" or prev_sig == "return"
        ):
            # regex literal
            j = i + 1
            in_class = False
            while j < n and text[j] != "\n":
                d = text[j]
                if d == "\\":
                    j += 2
                    continue
                if d == "[":
                    in_class = True
                elif d == "]":
                    in_class = False
                elif d == "/" and not in_class:
                    break
                j += 1
            if j < n and text[j] == "/":
                blank(i + 1, j)
                i = j + 1
                prev_sig = "/"
                continue
        if not c.isspace():
            prev_sig = c
        i += 1
    return "".join(out), strings


# ------------------------------------------------------------------------------- imports


_REQ_DESTRUCT = re.compile(r"(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\s*\(\s*([\"'])")
_REQ_NAMED = re.compile(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*([\"'])")
_IMP_DESTRUCT = re.compile(
    r"import\s+(?:type\s+)?(?:[A-Za-z_$][\w$]*\s*,\s*)?\{([^}]*)\}\s*from\s*([\"'])"
)
_IMP_DEFAULT = re.compile(r"import\s+([A-Za-z_$][\w$]*)\s*(?:,\s*\{[^}]*\}\s*)?from\s*([\"'])")
_IMP_NS = re.compile(r"import\s*\*\s*as\s+([A-Za-z_$][\w$]*)\s*from\s*([\"'])")
_IMP_BARE = re.compile(r"(?:import|export)\b[^;\n]*?\bfrom\s*([\"'])|^\s*import\s*([\"'])", re.M)
_REQ_ANY = re.compile(r"\brequire\s*\(\s*([\"'])")
_IMP_DYNAMIC_LITERAL = re.compile(r"\bimport\s*\(\s*([\"'])")


@dataclass
class _Imports:
    modules: dict[str, int]  # module name -> position of its import
    aliases: dict[str, str]  # local identifier -> module
    members: dict[str, tuple[str, str]]  # local identifier -> (module, exported name)


def _collect_imports(src: _Source) -> _Imports:
    m = src.masked
    imp = _Imports({}, {}, {})

    def module_at(quote_pos: int) -> str:
        return src.string_at(quote_pos)

    for rx in (_REQ_DESTRUCT, _IMP_DESTRUCT):
        for mt in rx.finditer(m):
            mod = module_at(mt.start(2))
            imp.modules.setdefault(mod, mt.start())
            for part in mt.group(1).split(","):
                part = part.strip()
                if not part or part.startswith("type "):
                    continue
                exported, _, local = part.replace(" as ", ":").partition(":")
                exported, local = exported.strip(), (local.strip() or exported.strip())
                imp.members[local] = (mod, exported)
    for rx in (_REQ_NAMED, _IMP_DEFAULT, _IMP_NS):
        for mt in rx.finditer(m):
            mod = module_at(mt.start(2))
            imp.modules.setdefault(mod, mt.start())
            imp.aliases[mt.group(1)] = mod
    for mt in _IMP_BARE.finditer(m):
        q = mt.start(1) if mt.group(1) else mt.start(2)
        imp.modules.setdefault(module_at(q), mt.start())
    for rx in (_REQ_ANY, _IMP_DYNAMIC_LITERAL):
        for mt in rx.finditer(m):
            imp.modules.setdefault(module_at(mt.start(1)), mt.start())
    return imp


# ------------------------------------------------------------------------------- sinks


_GLOBAL_SINKS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("network", "fetch", re.compile(r"(?<![\w$.])fetch\s*\(")),
    ("network", "WebSocket", re.compile(r"\bnew\s+WebSocket\s*\(")),
    ("network", "XMLHttpRequest", re.compile(r"\bnew\s+XMLHttpRequest\s*\(")),
    ("network", "navigator.sendBeacon", re.compile(r"\bnavigator\.sendBeacon\s*\(")),
    ("network", "Deno.connect", re.compile(r"\bDeno\.(?:connect|connectTls|listen)\s*\(")),
    ("dynamic_code", "eval", re.compile(r"(?<![\w$.])eval\s*\(")),
    ("dynamic_code", "new Function", re.compile(r"\bnew\s+Function\s*\(")),
    ("dynamic_code", "import()", re.compile(r"(?<![\w$.])import\s*\(\s*(?![\"'])[^)\s]")),
    ("dynamic_code", "require()", re.compile(r"(?<![\w$.])require\s*\(\s*(?![\"'])[^)\s]")),
    (
        "dynamic_code",
        "process.binding",
        re.compile(r"\bprocess\.(?:binding|_linkedBinding|dlopen)\s*\("),
    ),
    ("exec", "Deno.Command", re.compile(r"\bnew\s+Deno\.Command\s*\(|\bDeno\.run\s*\(")),
    ("exec", "Bun.spawn", re.compile(r"\bBun\.(?:spawn|spawnSync|\$)\s*[(`]")),
    (
        "fs_write",
        "Deno.writeFile",
        re.compile(r"\bDeno\.(?:writeFile|writeTextFile|mkdir|rename|copyFile|chmod|create)\s*\("),
    ),
    ("fs_delete", "Deno.remove", re.compile(r"\bDeno\.remove(?:Sync)?\s*\(")),
    (
        "fs_read",
        "Deno.readFile",
        re.compile(r"\bDeno\.(?:readFile|readTextFile|readDir|stat|open)\s*\("),
    ),
    ("fs_write", "Bun.write", re.compile(r"\bBun\.write\s*\(")),
    ("fs_read", "Bun.file", re.compile(r"\bBun\.file\s*\(")),
    ("env", "Deno.env", re.compile(r"\bDeno\.env\.(?:get|toObject)\s*\(")),
    ("native", "process.dlopen", re.compile(r"\bprocess\.dlopen\s*\(")),
)
_PROCESS_ENV = re.compile(
    r"\bprocess\.env\.([A-Za-z_$][\w$]*)|\bprocess\.env\[\s*([\"'])|\bBun\.env\.([A-Za-z_$][\w$]*)|\bprocess\.env(?![\w$.\[])"
)
_VM_CALLS = re.compile(
    r"\.(?:runInNewContext|runInThisContext|runInContext|compileFunction|Script)\s*\(|\bnew\s+(?:VM|NodeVM|Isolate)\s*\("
)


def _find_sinks(src: _Source, imp: _Imports) -> list[tuple[int, Sink]]:
    m = src.masked
    sinks: list[tuple[int, Sink]] = []

    def add(pos: int, cls: str, callee: str, detail: str | None = None) -> None:
        sinks.append((pos, Sink(cls, src.file, src.line_of(pos), callee, detail, src.snippet(pos))))

    def call_host(pos: int) -> str | None:
        paren = m.find("(", pos)
        if paren < 0:
            return None
        close = src.match_close(paren)
        for s in src.strings_in(paren, close):
            h = hosts_in(s)
            if h:
                return h[0]
        return None

    # module imports that are capabilities on their own
    for mod, pos in imp.modules.items():
        if mod in NETWORK_MODULES:
            add(pos, "network", f"import {mod}")
        elif mod in NATIVE_MODULES or mod.endswith(".node"):
            add(pos, "native", f"import {mod}")
        elif mod in ENV_MODULES:
            add(pos, "env", f"import {mod}")

    # identifier-bound sinks: alias.method( and destructured name(
    cp_aliases = {a for a, mod in imp.aliases.items() if mod in CHILD_PROCESS_MODULES}
    cp_names = {
        local: exp for local, (mod, exp) in imp.members.items() if mod in CHILD_PROCESS_MODULES
    }
    fs_aliases = {a for a, mod in imp.aliases.items() if mod in FS_MODULES}
    fs_names = {local: exp for local, (mod, exp) in imp.members.items() if mod in FS_MODULES}
    vm_aliases = {a for a, mod in imp.aliases.items() if mod in VM_MODULES} | {
        local for local, (mod, _) in imp.members.items() if mod in VM_MODULES
    }
    net_aliases = {a for a, mod in imp.aliases.items() if mod in NETWORK_MODULES} | {
        local for local, (mod, _) in imp.members.items() if mod in NETWORK_MODULES
    }

    def fs_class(method: str) -> str | None:
        if method in FS_WRITE:
            return "fs_write"
        if method in FS_DELETE:
            return "fs_delete"
        if method in FS_READ:
            return "fs_read"
        return None

    if cp_aliases:
        rx = re.compile(
            r"\b("
            + "|".join(map(re.escape, sorted(cp_aliases)))
            + r")\.("
            + "|".join(sorted(CHILD_PROCESS_METHODS - {"$", "x"}))
            + r")\s*\("
        )
        for mt in rx.finditer(m):
            add(
                mt.start(),
                "exec",
                f"child_process.{mt.group(2)}",
                _first_string_arg(src, mt.end() - 1),
            )
    if cp_names:
        rx = re.compile(r"(?<![\w$.])(" + "|".join(map(re.escape, sorted(cp_names))) + r")\s*[(`]")
        for mt in rx.finditer(m):
            add(
                mt.start(),
                "exec",
                f"child_process.{cp_names[mt.group(1)]}",
                _first_string_arg(src, mt.end() - 1),
            )
    if fs_aliases:
        rx = re.compile(
            r"\b("
            + "|".join(map(re.escape, sorted(fs_aliases)))
            + r")(?:\.promises)?\.([A-Za-z]+)\s*\("
        )
        for mt in rx.finditer(m):
            cls = fs_class(mt.group(2))
            if cls:
                add(mt.start(), cls, f"fs.{mt.group(2)}", _first_string_arg(src, mt.end() - 1))
    if fs_names:
        rx = re.compile(r"(?<![\w$.])(" + "|".join(map(re.escape, sorted(fs_names))) + r")\s*\(")
        for mt in rx.finditer(m):
            cls = fs_class(fs_names[mt.group(1)])
            if cls:
                add(
                    mt.start(),
                    cls,
                    f"fs.{fs_names[mt.group(1)]}",
                    _first_string_arg(src, mt.end() - 1),
                )
    if vm_aliases:
        for mt in _VM_CALLS.finditer(m):
            add(mt.start(), "dynamic_code", "vm." + mt.group(0).strip(".( "))
    if net_aliases:
        rx = re.compile(
            r"\b("
            + "|".join(map(re.escape, sorted(net_aliases)))
            + r")(?:\.[A-Za-z_$][\w$]*)*\s*\("
        )
        for mt in rx.finditer(m):
            add(mt.start(), "network", mt.group(0).rstrip("( "), call_host(mt.start()))

    for cls, callee, rx in _GLOBAL_SINKS:
        for mt in rx.finditer(m):
            detail = call_host(mt.start()) if cls == "network" else None
            if callee in ("eval", "new Function") or cls != "network":
                detail = (
                    _first_string_arg(src, m.find("(", mt.start()))
                    if cls in ("exec", "fs_write", "fs_delete", "fs_read")
                    else detail
                )
            add(mt.start(), cls, callee, detail)

    for mt in _PROCESS_ENV.finditer(m):
        name = mt.group(1) or mt.group(3)
        if mt.group(2):
            name = src.string_at(mt.start(2))
        add(mt.start(), "env", "process.env", name or None)

    # URL literals in a file that already talks to the network: record their hosts
    if any(s.cls == "network" for _, s in sinks):
        for s_pos, e_pos in src.strings:
            for h in hosts_in(src.text[s_pos:e_pos]):
                add(s_pos, "network", "url literal", h)
    return sinks


def _first_string_arg(src: _Source, paren_pos: int) -> str | None:
    if paren_pos < 0 or paren_pos >= len(src.masked) or src.masked[paren_pos] not in "(`":
        return None
    if src.masked[paren_pos] == "`":
        return src.string_at(paren_pos)[:120] or None
    close = src.match_close(paren_pos)
    first = src.masked.find('"', paren_pos, close)
    for q in ("'", "`"):
        alt = src.masked.find(q, paren_pos, close)
        if alt >= 0 and (first < 0 or alt < first):
            first = alt
    if first < 0:
        return None
    # only if the string is the first argument (nothing but whitespace before it)
    if src.masked[paren_pos + 1 : first].strip():
        return None
    return src.string_at(first)[:120] or None


# ------------------------------------------------------------------------------- ranges


_TOOL_CALL = re.compile(r"\.(?:tool|registerTool|addTool)\s*\(\s*([\"'])")
_TOOL_OBJ = re.compile(r"\.(?:tool|registerTool|addTool)\s*\(\s*\{")
_SWITCH = re.compile(r"\bswitch\s*\(([^)]*)\)\s*\{")
_CASE = re.compile(r"\bcase\s*([\"'])")
_IF_NAME = re.compile(
    r"\bif\s*\(\s*(?:[\w$.]*\b(?:name|toolName|tool)\b)\s*===?\s*([\"'])[^)]*\)\s*\{"
)
_DECLARED = re.compile(r"\bname\s*:\s*([\"'])")
_NAME_KEY = re.compile(r"\bname\s*:\s*([\"'])")


def _function_ranges(src: _Source) -> list[_Range]:
    m = src.masked
    out: list[_Range] = []
    seen: set[int] = set()
    for rx in _DEF_RES:
        for mt in rx.finditer(m):
            name = mt.group(1)
            if name in _KEYWORDS:
                continue
            brace = m.find("{", mt.end() - 1 if m[mt.end() - 1 : mt.end()] == "{" else mt.end())
            if brace < 0:
                continue
            # the brace must follow without an intervening statement terminator
            between = m[mt.end() : brace]
            if ";" in between or "\n\n" in between:
                continue
            if brace in seen:
                continue
            seen.add(brace)
            end = src.match_close(brace)
            out.append(
                _Range(
                    mt.start(),
                    end,
                    f"{src.file}::{name}#{src.line_of(mt.start())}",
                    name,
                    src.line_of(mt.start()),
                )
            )
    return out


def _tool_ranges(src: _Source, res: ModuleResult) -> list[_Range]:
    m = src.masked
    out: list[_Range] = []

    def add(name: str, start: int, end: int) -> None:
        key = f"{src.file}::tool:{name}"
        out.append(_Range(start, end, key, f"tool:{name}", src.line_of(start), is_tool=True))
        res.tools.setdefault(name, key)

    for mt in _TOOL_CALL.finditer(m):
        name = src.string_at(mt.start(1))
        paren = m.rfind("(", 0, mt.start(1))
        if name and paren >= 0:
            add(name, paren, src.match_close(paren))
    for mt in _TOOL_OBJ.finditer(m):
        paren = m.rfind("(", 0, mt.end())
        brace = mt.end() - 1
        obj_end = src.match_close(brace)
        nm = _NAME_KEY.search(m, brace, obj_end)
        if nm and paren >= 0:
            name = src.string_at(nm.start(1))
            if name:
                add(name, paren, src.match_close(paren))
    for mt in _SWITCH.finditer(m):
        if "name" not in mt.group(1).lower() and "tool" not in mt.group(1).lower():
            continue
        brace = mt.end() - 1
        end = src.match_close(brace)
        cases = list(_CASE.finditer(m, brace, end))
        for i, cm in enumerate(cases):
            name = src.string_at(cm.start(1))
            nxt = cases[i + 1].start() if i + 1 < len(cases) else end
            dflt = re.compile(r"\bdefault\s*:").search(m, cm.end(), nxt)
            if name:
                add(name, cm.start(), dflt.start() if dflt else nxt)
    for mt in _IF_NAME.finditer(m):
        name = src.string_at(mt.start(1))
        brace = mt.end() - 1
        if name:
            add(name, mt.start(), src.match_close(brace))
    for mt in _DECLARED.finditer(m):
        window = m[max(0, mt.start() - 400) : mt.start() + 400]
        if "description" in window or "inputSchema" in window:
            name = src.string_at(mt.start(1))
            if name and " " not in name:
                res.declared.add(name)
    return out


_CALL_RE = re.compile(r"(?<![\w$])\.?([A-Za-z_$][\w$]*)\s*\(")


def analyse_javascript(file: str, text: str) -> ModuleResult:
    src = _Source(file, text)
    res = ModuleResult(
        file=file,
        attribution="lexical",
        module_name=re.sub(r"\.[^.]+$", "", file.rsplit("/", 1)[-1]),
    )
    if any(len(ln) > 3000 for ln in src.lines):
        res.notes.append(f"{file}: minified or bundled; handler attribution is unreliable")
    imp = _collect_imports(src)
    positioned = _find_sinks(src, imp)
    res.sinks = [s for _, s in positioned]

    ranges = _function_ranges(src) + _tool_ranges(src, res)
    for r in ranges:
        res.functions.setdefault(
            r.key, FunctionInfo(key=r.key, name=r.name, file=file, line=r.line)
        )

    def innermost(pos: int) -> _Range | None:
        best: _Range | None = None
        for r in ranges:
            if r.start <= pos < r.end and (
                best is None or (r.end - r.start) < (best.end - best.start)
            ):
                best = r
        return best

    # sinks -> enclosing function (innermost named function, or tool range)
    for pos, s in positioned:
        owner = innermost(pos)
        if owner is not None:
            res.functions[owner.key].sinks.append(s)
    # calls -> enclosing function
    for mt in _CALL_RE.finditer(src.masked):
        name = mt.group(1)
        if name in _KEYWORDS:
            continue
        caller = innermost(mt.start())
        if caller is not None and caller.name != name:
            res.functions[caller.key].calls.add(name)
    return res
