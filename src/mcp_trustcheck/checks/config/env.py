"""CFG-008: code-injection environment variables (threat-model.md T6)."""

from __future__ import annotations

import re

from mcp_trustcheck.checks import Context, emit, register
from mcp_trustcheck.model import Affected, Finding, ServerConfig, Severity

HIGH_RISK = {
    "LD_PRELOAD",
    "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "BASH_ENV",
    "ENV",
    "PROMPT_COMMAND",
    "PYTHONSTARTUP",
    "PERL5OPT",
    "RUBYOPT",
}
MEDIUM_RISK = {
    "NODE_OPTIONS",
    "NODE_PATH",
    "LD_LIBRARY_PATH",
    "PYTHONPATH",
    "PYTHONHOME",
    "PERL5LIB",
    "RUBYLIB",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "CLASSPATH",
    "GIT_SSH_COMMAND",
    "GIT_EXEC_PATH",
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
}
_NODE_LOAD_RE = re.compile(r"(?:^|\s)(?:-r|--require|--import|--loader|--experimental-loader)\b")


@register("CFG-008", "config")
def check_env_injection(server: ServerConfig, ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    for key, cv in server.env.items():
        k = key.upper()
        if k in HIGH_RISK:
            sev, why = (
                Severity.HIGH,
                "loads arbitrary code into the process before the server starts",
            )
        elif k in MEDIUM_RISK:
            sev, why = Severity.MEDIUM, "changes what code or trust material the runtime loads"
            if k == "NODE_OPTIONS" and _NODE_LOAD_RE.search(cv.value):
                sev, why = Severity.HIGH, "NODE_OPTIONS preloads a module into the server process"
        else:
            continue
        findings.append(
            emit(
                ctx,
                "CFG-008",
                affected=Affected(server.source_file, cv.json_path, server=server.name),
                evidence=[(cv.json_path, f"{key}={cv.value}", why)],
                description=f"Server '{server.name}' sets `{key}`, which {why}.",
                severity=sev,
                key=key,
            )
        )
    return findings
