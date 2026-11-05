"""Single source of truth for rule metadata (threat-model.md §6).

Only rules that are actually implemented appear here; the `rules` command, the checks and the
README tables all read from this module so they cannot drift apart.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from mcp_trustcheck.model import Confidence, Kind, Reference, Severity, Standard

SPEC = "https://modelcontextprotocol.io/specification/2026-07-28"
BEST_PRACTICES = (
    "https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices"
)

REF_LOCAL_COMPROMISE = Reference(
    "MCP Security Best Practices — Local MCP Server Compromise",
    f"{BEST_PRACTICES}#local-mcp-server-compromise",
)
REF_TOKEN_PASSTHROUGH = Reference(
    "MCP Security Best Practices — Token Passthrough", f"{BEST_PRACTICES}#token-passthrough"
)
REF_SCOPE_MIN = Reference(
    "MCP Security Best Practices — Scope Minimization", f"{BEST_PRACTICES}#scope-minimization"
)
REF_STREAMABLE_HTTP = Reference(
    "MCP Streamable HTTP transport — Security & Endpoint",
    f"{SPEC}/basic/transports/streamable-http#security--endpoint",
)
REF_AUTHZ = Reference("MCP Authorization specification", f"{SPEC}/basic/authorization")
REF_TOOLS = Reference("MCP Tools specification", f"{SPEC}/server/tools")
REF_TOOLS_UI = Reference(
    "MCP Tools specification — User Interaction Model",
    f"{SPEC}/server/tools#user-interaction-model",
)
REF_INVARIANT = Reference(
    "Invariant Labs — MCP Security Notification: Tool Poisoning Attacks",
    "https://invariantlabs.ai/blog/mcp-security-notification",
)
REF_CSA = Reference(
    "Cloud Security Alliance — MCP Tool Poisoning and Rug Pull Attacks (2026)",
    "https://labs.cloudsecurityalliance.org/research-rb/csa-whitepaper-mcp-security-tool-poisoning-20260506-csa-styl/",
)
REF_OWASP_MCP03 = Reference(
    "OWASP MCP Top 10 (beta) — MCP03 Tool Poisoning",
    "https://owasp.org/www-project-mcp-top-10/",
)
REF_OWASP_SECRETS = Reference(
    "OWASP Secrets Management Cheat Sheet",
    "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
)
REF_NPM_SCRIPTS = Reference(
    "npm Docs — scripts: life cycle scripts run on install",
    "https://docs.npmjs.com/cli/v10/using-npm/scripts#life-cycle-scripts",
)
REF_OWASP_MCP04 = Reference(
    "OWASP MCP Top 10 (beta) — MCP04 Software Supply Chain Attacks & Dependency Tampering",
    "https://owasp.org/www-project-mcp-top-10/",
)
REF_TOOLS_ANNOTATIONS = Reference(
    "MCP Tools specification — Tool Annotations (hints, not guarantees)",
    f"{SPEC}/server/tools#tool-annotations",
)
REF_OAUTH21 = Reference(
    "OAuth 2.1 — TLS requirements (§1.5)",
    "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13#section-1.5",
)


# --------------------------------------------------------------------------- standards
# Stable identifiers a reviewer can cite or map to a control framework. CWE entries are the
# MITRE weakness taxonomy; the OWASP MCP Top 10 (2025, beta) and the OWASP Top 10 for LLM
# Applications (2025) are the two risk catalogues closest to this tool's scope. Each rule maps to
# at least one CWE. Titles are reproduced verbatim from the source at the time of writing.

CWE_URL = "https://cwe.mitre.org/data/definitions/{n}.html"
OWASP_MCP_URL = "https://owasp.org/www-project-mcp-top-10/"
OWASP_LLM_URL = "https://genai.owasp.org/llm-top-10/"


def _cwe(n: int, title: str) -> Standard:
    return Standard("CWE", f"CWE-{n}", title, CWE_URL.format(n=n))


def _mcp(n: str, title: str) -> Standard:
    return Standard("OWASP MCP Top 10", f"MCP{n}:2025", title, OWASP_MCP_URL)


def _llm(n: str, title: str) -> Standard:
    return Standard("OWASP LLM Top 10", f"LLM{n}:2025", title, OWASP_LLM_URL)


CWE_20 = _cwe(20, "Improper Input Validation")
CWE_78 = _cwe(
    78, "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"
)
CWE_94 = _cwe(94, "Improper Control of Generation of Code ('Code Injection')")
CWE_200 = _cwe(200, "Exposure of Sensitive Information to an Unauthorized Actor")
CWE_250 = _cwe(250, "Execution with Unnecessary Privileges")
CWE_269 = _cwe(269, "Improper Privilege Management")
CWE_284 = _cwe(284, "Improper Access Control")
CWE_306 = _cwe(306, "Missing Authentication for Critical Function")
CWE_312 = _cwe(312, "Cleartext Storage of Sensitive Information")
CWE_319 = _cwe(319, "Cleartext Transmission of Sensitive Information")
CWE_345 = _cwe(345, "Insufficient Verification of Data Authenticity")
CWE_427 = _cwe(427, "Uncontrolled Search Path Element")
CWE_451 = _cwe(451, "User Interface (UI) Misrepresentation of Critical Information")
CWE_477 = _cwe(477, "Use of Obsolete Function")
CWE_494 = _cwe(494, "Download of Code Without Integrity Check")
CWE_506 = _cwe(506, "Embedded Malicious Code")
CWE_522 = _cwe(522, "Insufficiently Protected Credentials")
CWE_523 = _cwe(523, "Unprotected Transport of Credentials")
CWE_668 = _cwe(668, "Exposure of Resource to Wrong Sphere")
CWE_694 = _cwe(694, "Use of Multiple Resources with Duplicate Identifier")
CWE_798 = _cwe(798, "Use of Hard-coded Credentials")
CWE_829 = _cwe(829, "Inclusion of Functionality from Untrusted Control Sphere")
CWE_862 = _cwe(862, "Missing Authorization")
CWE_1059 = _cwe(1059, "Insufficient Technical Documentation")
CWE_1327 = _cwe(1327, "Binding to an Unrestricted IP Address")
CWE_1427 = _cwe(1427, "Improper Neutralization of Input Used for LLM Prompting")

OWASP_MCP01 = _mcp("01", "Token Mismanagement & Secret Exposure")
OWASP_MCP02 = _mcp("02", "Privilege Escalation via Scope Creep")
OWASP_MCP03 = _mcp("03", "Tool Poisoning")
OWASP_MCP04 = _mcp("04", "Software Supply Chain Attacks & Dependency Tampering")
OWASP_MCP05 = _mcp("05", "Command Injection & Execution")
OWASP_MCP06 = _mcp("06", "Prompt Injection via Contextual Payloads")
OWASP_MCP07 = _mcp("07", "Insufficient Authentication & Authorization")
OWASP_MCP09 = _mcp("09", "Shadow MCP Servers")
OWASP_MCP10 = _mcp("10", "Context Injection & Over-Sharing")

OWASP_LLM01 = _llm("01", "Prompt Injection")
OWASP_LLM02 = _llm("02", "Sensitive Information Disclosure")
OWASP_LLM03 = _llm("03", "Supply Chain")
OWASP_LLM06 = _llm("06", "Excessive Agency")


@dataclass(frozen=True)
class RuleMeta:
    id: str
    title: str
    threat: str  # T-id from threat-model.md §3
    property: str  # the security property evaluated
    kind: Kind
    severity: Severity  # default; checks may raise or lower with a stated reason
    confidence: Confidence  # default
    impact: str
    mitigation: str
    limitations: str
    references: tuple[Reference, ...] = field(default_factory=tuple)
    standards: tuple[Standard, ...] = field(default_factory=tuple)  # CWE / OWASP identifiers
    spec_note: str | None = None
    detection: str = ""  # human-readable summary of the detection logic


RULES: dict[str, RuleMeta] = {}


def _add(rule: RuleMeta) -> None:
    RULES[rule.id] = rule


_add(
    RuleMeta(
        id="CFG-003",
        title="Shell-mediated server execution",
        threat="T6",
        property="The command that launches a local server is a direct executable invocation whose "
        "arguments cannot be re-interpreted by a shell.",
        kind=Kind.WEAKNESS,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        impact="A shell wrapper lets a config entry chain arbitrary commands (download-and-execute, "
        "data exfiltration, destructive operations) that run with the MCP client's privileges, "
        "and makes the real command harder for a reviewer to see.",
        mitigation='Launch the server executable directly (`command: "npx"`, args as a list). '
        "If a shell is unavoidable (e.g. Windows `cmd /c` for a `.cmd` shim), keep the payload a "
        "single plain command with no metacharacters, and review it in full before approving.",
        limitations="Cannot see inside wrapper scripts (`bash run.sh`); such entries are reported at "
        "reduced severity. Metacharacters in the argv of a non-shell command are reported as Info "
        "because most clients spawn without a shell, but a client that does use one would make them "
        "live.",
        references=(REF_LOCAL_COMPROMISE,),
        standards=(CWE_78, OWASP_MCP05),
        detection="`command` basename is a shell; `-c`/`/c`/`-Command`/`-EncodedCommand` present; "
        "payload inspected for `&&`, `;`, `|`, `$(`, backticks, redirections.",
    )
)

_add(
    RuleMeta(
        id="CFG-005",
        title="Hardcoded credential in configuration",
        threat="T9",
        property="Credentials are supplied at runtime (environment or client secret store), not stored "
        "as plaintext in a configuration file.",
        kind=Kind.WEAKNESS,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        impact="Anyone who can read the file — other local users, backup/sync tools, a repository the "
        "file is committed to, or any process running as the user — obtains the credential. Config "
        "files are routinely shared in bug reports and screenshots.",
        mitigation="Reference the secret instead of embedding it (`${env:NAME}`, VS Code `inputs`, "
        "or the client's credential store). Rotate any credential that has been written to disk in "
        "plaintext.",
        limitations="Known-prefix matches are reliable; key-name and entropy matches are heuristics "
        "and may flag opaque identifiers that are not secrets. Low-entropy passwords without a "
        "recognisable key name are missed.",
        references=(REF_OWASP_SECRETS, REF_TOKEN_PASSTHROUGH),
        standards=(CWE_798, CWE_312, OWASP_MCP01, OWASP_LLM02),
        detection="Literal `env`, `headers`, URL userinfo/query and argv values matched against known "
        "token prefixes (high confidence), then secret-like key names (medium), then high-entropy "
        "strings (low). `${...}` references and placeholders are excluded. Output is always "
        "redacted.",
    )
)

_add(
    RuleMeta(
        id="CFG-006",
        title="Over-broad filesystem access",
        threat="T5",
        property="A filesystem-capable server is restricted to the directories the task actually needs.",
        kind=Kind.WEAKNESS,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        impact="Any prompt injection or poisoned tool that reaches this server can read or modify "
        "everything under the exposed root: SSH keys, cloud credentials, browser profiles, other "
        "projects. Exposing `/` or the home directory removes the only boundary the server has.",
        mitigation="Pass only the specific project directories the server needs. Prefer several narrow "
        "roots over one broad one. For Docker-based servers, mount specific paths read-only where "
        "possible.",
        limitations="Only recognises filesystem servers by well-known package names, directory-style "
        "flags, environment variables, and Docker volume mounts. A server that exposes paths through an "
        "unrecognised mechanism is missed. Windows paths are matched as strings, not resolved.",
        references=(REF_LOCAL_COMPROMISE, REF_SCOPE_MIN),
        standards=(CWE_250, CWE_284, OWASP_MCP02, OWASP_LLM06),
        detection="Collect directory arguments; flag filesystem roots and drive roots (High), home "
        "directories and system directories (Medium), and credential directories such as `~/.ssh` "
        "or `~/.aws` (High).",
    )
)

_add(
    RuleMeta(
        id="CFG-009",
        title="Plaintext transport to a remote MCP server",
        threat="T10",
        property="Remote MCP traffic — and any bearer credential it carries — is protected by TLS.",
        kind=Kind.WEAKNESS,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        impact="Tool calls, results and any `Authorization` header cross the network in the clear and "
        "can be read or modified by anyone on the path. With a bearer token present the token itself "
        "is exposed.",
        mitigation="Use `https://` (or `wss://`). For local development use a loopback address, which "
        "the OAuth 2.1 and MCP specifications treat as the only acceptable plaintext exception.",
        limitations="Cannot know whether the network path is already protected (VPN, service mesh, SSH "
        "tunnel). Private-range hosts are reported with a note to that effect.",
        references=(REF_STREAMABLE_HTTP, REF_OAUTH21, REF_AUTHZ),
        standards=(CWE_319, CWE_523, OWASP_MCP01, OWASP_MCP07),
        spec_note="Loopback exception per OAuth 2.1 §1.5 and MCP Security Best Practices (SSRF "
        "section: 'Reject http:// URLs except for loopback addresses').",
        detection="`url` scheme is `http` or `ws` and host is not loopback. Severity raised to High "
        "when an Authorization-style header or credential-bearing URL is present.",
    )
)

_add(
    RuleMeta(
        id="CFG-013",
        title="Tool approval bypassed (auto-approve / trust)",
        threat="T11",
        property="A human can see and deny each tool invocation (MCP Tools spec: there SHOULD always be "
        "a human in the loop).",
        kind=Kind.WEAKNESS,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        impact="Removes the consent step that limits tool poisoning, rug pulls and indirect prompt "
        "injection. Published measurements of poisoning success are highest when tool calls are "
        "auto-approved. A wildcard means every present *and future* tool runs unprompted.",
        mitigation="Remove wildcard approvals. Auto-approve only specific read-only tools you have "
        "reviewed, and re-review when the server updates.",
        limitations="Approval keys are client-specific (`autoApprove`, `alwaysAllow`, `trust`); other "
        "clients configure approval outside the server entry and are not visible here.",
        references=(REF_TOOLS_UI, REF_INVARIANT),
        standards=(CWE_862, OWASP_MCP02, OWASP_LLM06),
        detection="Server entry contains `autoApprove`/`alwaysAllow` with entries, or `trust: true`. "
        "Wildcard (`*`, `true`) raises severity to High.",
    )
)

_add(
    RuleMeta(
        id="TOOL-001",
        title="Agent-directed instructions in tool metadata",
        threat="T1",
        property="Tool metadata describes behaviour to the model; it does not instruct the model, "
        "reference unrelated files or other tools, or ask for concealment from the user.",
        kind=Kind.INDICATOR,
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        impact="Tool descriptions and schemas are delivered into the model's context verbatim. "
        "Embedded instructions can redirect the agent to read secrets, pass them as hidden "
        "arguments, alter calls to other tools, or hide activity from the user (tool poisoning).",
        mitigation="Treat the server as untrusted until a human has read every string in its tool "
        "definitions. Prefer clients that display full descriptions, pin approved definitions "
        "(see TOOL-006), and keep sensitive-capability servers in separate sessions.",
        limitations="This is a lexical indicator, not a verdict: legitimate documentation can use "
        "imperative language, and a determined attacker can paraphrase or write in another "
        "language. Static analysis cannot determine whether a tool is malicious.",
        references=(REF_INVARIANT, REF_OWASP_MCP03, REF_CSA, REF_TOOLS),
        standards=(CWE_1427, OWASP_MCP03, OWASP_MCP06, OWASP_LLM01),
        detection="All strings in description, title, parameter descriptions, enum/default values and "
        "output schema are matched against six signal classes: model-directed imperatives, "
        "concealment from the user, pseudo system tags, sensitive file references, exfiltration "
        "channels, and cross-tool manipulation. Confidence scales with the number of distinct classes.",
    )
)

_add(
    RuleMeta(
        id="TOOL-006",
        title="Tool definition changed since approved baseline",
        threat="T2",
        property="The tool definitions in use are the ones a human reviewed and approved.",
        kind=Kind.WEAKNESS,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        impact="A server can change a description, schema or annotations after approval (a 'rug pull'); "
        "the protocol explicitly allows the tool set to change over time. Instructions added later "
        "reach the model without a new consent step.",
        mitigation="Re-review every changed and added tool before continuing to use the server; "
        "update the baseline only after review. Consider clients that pin tool definitions by hash.",
        limitations="Any legitimate update also triggers this finding — that is the intended behaviour. "
        "Comparison is offline between two snapshots; it does not observe live changes.",
        references=(REF_INVARIANT, REF_CSA, REF_TOOLS),
        standards=(CWE_345, CWE_829, OWASP_MCP03, OWASP_MCP04, OWASP_LLM03),
        spec_note="MCP 2026-07-28 Tools spec: the tool set 'MAY change over time'; clients subscribed "
        "via subscriptions/listen receive notifications/tools/list_changed.",
        detection="SHA-256 over the canonical JSON of {name,title,description,inputSchema,outputSchema,"
        "annotations} per tool; added, removed and changed tools are reported with a field-level diff.",
    )
)


REF_OWASP_MCP05 = Reference(
    "OWASP MCP Top 10 (beta) — MCP05 Command Injection & Execution",
    "https://owasp.org/www-project-mcp-top-10/2025/MCP05-2025%E2%80%93Command-Injection&Execution.html",
)
REF_TOOLS_XHEADER = Reference(
    "MCP Tools specification — x-mcp-header", f"{SPEC}/server/tools#x-mcp-header"
)
REF_TOOLS_NAMES = Reference(
    "MCP Tools specification — Tool Names", f"{SPEC}/server/tools#tool-names"
)
REF_TOOLS_SECURITY = Reference(
    "MCP Tools specification — Security Considerations",
    f"{SPEC}/server/tools#security-considerations",
)
REF_DEPRECATED = Reference("MCP deprecated features registry", f"{SPEC}/deprecated")
REF_CYBERARK = Reference(
    "CyberArk Labs — Poison everywhere: no output from your MCP server is safe (2025)",
    "https://www.cyberark.com/resources/threat-research-blog/poison-everywhere-no-output-from-your-mcp-server-is-safe",
)

_add(
    RuleMeta(
        id="CFG-001",
        title="Unpinned package executed at launch",
        threat="T6",
        property="The code that runs as an MCP server is a known, reviewed version.",
        kind=Kind.WEAKNESS,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        impact="`npx`/`uvx`-style launchers resolve the package at every start. Without a pinned version, "
        "a compromised or typosquatted release is executed with the client's privileges the next "
        "time the server starts — a supply-chain path that needs no user interaction.",
        mitigation="Pin an exact version (`pkg@1.2.3`, `pkg==1.2.3`, a git commit SHA) and update "
        "deliberately. Prefer installing the server once and launching the installed binary.",
        limitations="Pinning limits drift; it does not vouch for the pinned version. Lockfiles outside "
        "the config file are not consulted. Only well-known launchers are recognised.",
        references=(REF_LOCAL_COMPROMISE, REF_CSA),
        standards=(CWE_829, CWE_494, OWASP_MCP04, OWASP_LLM03),
        detection="`command` is npx/bunx/pnpm dlx/uvx/pipx run; the package argument has no exact "
        "version (no `@x.y.z`/`==x.y.z`, or a range/tag such as `latest`, `^`, `>=`).",
    )
)
_add(
    RuleMeta(
        id="CFG-002",
        title="Unexpected executable or inline interpreter code",
        threat="T6",
        property="The server executable is a stable, reviewable program, not a transient file or an inline script.",
        kind=Kind.INDICATOR,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        impact="A binary in a temp, download or cache directory can be replaced without notice; inline "
        "code (`python -c`, `node -e`) hides the server's logic inside the config entry where it is "
        "rarely reviewed.",
        mitigation="Install servers to a stable location and reference the installed path or launcher; "
        "move inline code into a versioned file.",
        limitations="Directory conventions are platform-specific heuristics; a legitimate development "
        "setup may run from these locations.",
        references=(REF_LOCAL_COMPROMISE,),
        standards=(CWE_829, OWASP_MCP05, OWASP_LLM03),
        detection="Command path under /tmp, /var/tmp, Downloads, Temp, or cache dirs; or an interpreter "
        "invoked with `-c`/`-e`/`--eval` and an inline program.",
    )
)
_add(
    RuleMeta(
        id="CFG-004",
        title="Dangerous command content",
        threat="T6",
        property="A server launch command does not escalate privilege, destroy data, download-and-execute, "
        "or touch credential stores (patterns the MCP spec tells clients to highlight).",
        kind=Kind.WEAKNESS,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        impact="These idioms are the payloads of the attack the specification describes: a config entry "
        "that exfiltrates keys, installs persistence, or wipes files when the client starts the server.",
        mitigation="Remove the pattern. A legitimate server never needs `sudo`, `rm -rf`, piping a "
        "download into a shell, or reading `~/.ssh` from its launch command.",
        limitations="Pattern-based; a maintenance script may legitimately use some of these. Obfuscated "
        "variants (string splitting, encoding) are not decoded.",
        references=(REF_LOCAL_COMPROMISE, REF_OWASP_MCP05),
        standards=(CWE_78, CWE_494, CWE_250, OWASP_MCP05),
        detection="Command line matched for privilege escalation, destructive deletion, download-to-shell, "
        "reverse shells, decode-and-run, and credential paths. Severity by class.",
    )
)
_add(
    RuleMeta(
        id="CFG-007",
        title="Privileged container launch",
        threat="T5",
        property="A containerised server runs with the minimal privileges the sandbox is meant to provide.",
        kind=Kind.WEAKNESS,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        impact="`--privileged`, a mounted Docker socket, host network/PID namespaces or added "
        "capabilities give the container (and anything that compromises it) host-level access, "
        "defeating the reason it was containerised.",
        mitigation="Drop the flag. Mount only needed paths, keep the default network namespace, add no "
        "capabilities, and never mount the container runtime socket.",
        limitations="Only `docker`/`podman`/`nerdctl run` command lines are inspected; compose files and "
        "runtime defaults are not.",
        references=(REF_LOCAL_COMPROMISE,),
        standards=(CWE_250, CWE_269, OWASP_MCP02, OWASP_LLM06),
        detection="Flags: --privileged, --network/--net host, --pid host, --ipc host, --userns host, "
        "--cap-add (SYS_ADMIN/ALL/…), --security-opt *unconfined, docker.sock mount, --user root/0.",
    )
)
_add(
    RuleMeta(
        id="CFG-008",
        title="Code-injection environment variable",
        threat="T6",
        property="The server process loads only the code of the server (hypothesis: loader/interpreter "
        "environment variables alter process behaviour before the server runs).",
        kind=Kind.INDICATOR,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        impact="Variables such as NODE_OPTIONS, LD_PRELOAD, DYLD_INSERT_LIBRARIES, PYTHONPATH or BASH_ENV "
        "make the runtime load extra code at start-up. In a shared or copied config they are a quiet "
        "way to hook a legitimate server.",
        mitigation="Remove the variable, or document exactly why the server needs it and what it loads.",
        limitations="Some development setups set these legitimately (module paths, debuggers).",
        references=(REF_LOCAL_COMPROMISE,),
        standards=(CWE_427, CWE_94, OWASP_MCP05),
        detection="`env` contains a known loader/interpreter hook variable. Preload-style variables "
        "and NODE_OPTIONS with --require/--import are raised to High.",
    )
)
_add(
    RuleMeta(
        id="CFG-010",
        title="Deprecated HTTP+SSE transport",
        threat="T10",
        property="Remote servers use the current Streamable HTTP transport.",
        kind=Kind.WEAKNESS,
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        impact="The 2024-11-05 HTTP+SSE transport is deprecated and eligible for removal; it predates the "
        "Origin-validation, header-mirroring and authorization hardening of later revisions, and "
        "support will disappear from clients and SDKs.",
        mitigation="Migrate the server and the config entry to Streamable HTTP.",
        limitations='Detection relies on `type: "sse"` or a URL ending in `/sse`; a legacy server '
        "behind a different path is missed.",
        references=(REF_STREAMABLE_HTTP, REF_DEPRECATED),
        standards=(CWE_477, OWASP_MCP07),
        spec_note="Deprecated since 2025-03-26; formally Deprecated under the feature-lifecycle policy "
        "in 2026-07-28 with a twelve-month minimum window.",
        detection="transport resolves to `sse`.",
    )
)
_add(
    RuleMeta(
        id="CFG-011",
        title="Local HTTP server bound to all interfaces",
        threat="T10",
        property="A locally run HTTP server listens on loopback only (spec: SHOULD bind to 127.0.0.1).",
        kind=Kind.WEAKNESS,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        impact="Binding to 0.0.0.0/:: exposes the MCP endpoint to the LAN and, combined with missing "
        "Origin checks or authentication, to any website via DNS rebinding.",
        mitigation="Bind to 127.0.0.1 (or a Unix socket) and require authentication if the server must "
        "be reachable by other hosts.",
        limitations="Only recognises common host flags/env vars. Inside a container 0.0.0.0 is often "
        "required and the exposure is governed by the port mapping instead.",
        references=(REF_STREAMABLE_HTTP,),
        standards=(CWE_1327, CWE_668, OWASP_MCP07, OWASP_MCP09),
        detection="`--host`/`--bind`/`-H` or HOST-style env set to 0.0.0.0, ::, or *. High when no "
        "credential-like env/arg is present.",
    )
)
_add(
    RuleMeta(
        id="CFG-012",
        title="Remote server with no visible authentication",
        threat="T8",
        property="Remote servers authenticate connections (spec: servers SHOULD implement authentication).",
        kind=Kind.INFO,
        severity=Severity.INFO,
        confidence=Confidence.LOW,
        impact="If the server really is unauthenticated, anyone who can reach it can use its tools. "
        "Reported as information because OAuth discovery happens at runtime and is invisible here.",
        mitigation="Confirm the server performs OAuth 2.1 discovery or otherwise authenticates; if it "
        "is intentionally public, make sure it exposes nothing sensitive.",
        limitations="Cannot observe runtime authorization. Expect this on every OAuth-protected server.",
        references=(REF_AUTHZ, REF_STREAMABLE_HTTP),
        standards=(CWE_306, OWASP_MCP07),
        detection="Non-loopback `url` with no `headers` and no auth-related keys in the entry.",
    )
)
_add(
    RuleMeta(
        id="CFG-014",
        title="Duplicate server definitions",
        threat="T3",
        property="Each server is defined once, so a reviewer knows which entry is in effect.",
        kind=Kind.INFO,
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        impact="Two entries launching the same package or URL under different names doubles the attack "
        "surface and makes approvals ambiguous (which one did the user approve?).",
        mitigation="Remove the redundant entry.",
        limitations="Only within one file. Cross-file precedence (user vs project config) is "
        "client-specific and not evaluated.",
        references=(REF_TOOLS_NAMES,),
        standards=(CWE_694, OWASP_MCP09),
        detection="Two servers in one file with the same command line or URL.",
    )
)
_add(
    RuleMeta(
        id="CFG-015",
        title="Sensitive parameter mirrored into an HTTP header",
        threat="T9",
        property="Parameters marked `x-mcp-header` carry no secrets or PII (spec: servers SHOULD NOT).",
        kind=Kind.WEAKNESS,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        impact="Header values are visible to every intermediary — load balancers, WAFs, logging — "
        "so a mirrored token or personal identifier is exposed far beyond the server.",
        mitigation="Remove `x-mcp-header` from the parameter; keep secrets in the request body only.",
        limitations="Decided from the parameter's name and description; a parameter literally named "
        "`token` that is not secret is a false positive.",
        references=(REF_TOOLS_XHEADER,),
        standards=(CWE_200, CWE_522, OWASP_MCP01, OWASP_LLM02),
        spec_note="`x-mcp-header` exists only in MCP 2026-07-28 and later.",
        detection="A statically reachable property with `x-mcp-header` whose name or description "
        "matches secret or PII vocabulary.",
    )
)
_add(
    RuleMeta(
        id="TOOL-002",
        title="Hidden or obfuscated content in tool metadata",
        threat="T1",
        property="Everything the model reads in a tool definition is visible to a human reviewer.",
        kind=Kind.INDICATOR,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        impact="Zero-width and bidirectional characters, Unicode tag characters, HTML comments, long "
        "encoded blobs and whitespace padding let instructions reach the model while the UI shows "
        "something innocuous.",
        mitigation="Reject definitions containing invisible characters; render descriptions with "
        "escapes visible before approving.",
        limitations="Length-based signals (padding, outliers) are heuristics; right-to-left languages "
        "and emoji are allowed and not flagged.",
        references=(REF_INVARIANT, REF_CYBERARK, REF_CSA),
        standards=(CWE_1427, CWE_506, OWASP_MCP03, OWASP_LLM01),
        detection="Zero-width/bidi/tag code points (High confidence); HTML comments; base64/hex runs "
        "≥ 64 chars; whitespace runs ≥ 100; description > 5x the catalogue median and > 2000 chars.",
    )
)
_add(
    RuleMeta(
        id="TOOL-004",
        title="Annotation contradicts apparent capability",
        threat="T1",
        property="Tool annotations are consistent with what the tool evidently does (spec: annotations "
        "are untrusted hints; clients fall back to worst-case assumptions when absent).",
        kind=Kind.INDICATOR,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        impact="Clients that gate confirmation on `readOnlyHint`/`destructiveHint` will skip the prompt "
        "for a tool that executes commands, writes, deletes or sends data if the server mislabels it.",
        mitigation="Correct the annotations, or treat the server as untrusted so the client ignores "
        "them. Never rely on annotations from a server you did not vet.",
        limitations="Capability is inferred from names and descriptions; `remove_filter` or "
        "`get_updates` can mislead the inference.",
        references=(REF_TOOLS, REF_TOOLS_SECURITY),
        standards=(CWE_451, OWASP_MCP03, OWASP_LLM06),
        detection="Capability class (exec, write, delete, send) inferred from name tokens, then first "
        "sentence; compared with readOnlyHint/destructiveHint. Missing annotations on a sensitive "
        "tool are reported as Info.",
    )
)
_add(
    RuleMeta(
        id="TOOL-005",
        title="Underspecified tool definition",
        threat="T7",
        property="A tool declares what it does and constrains what it accepts (spec: inputSchema MUST be "
        "a valid object; servers MUST validate inputs).",
        kind=Kind.INDICATOR,
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        impact="A free-form `command`/`sql`/`path` string with no constraints is the shape of every "
        "published MCP command-injection CVE; a missing description leaves the model (and the "
        "reviewer) guessing what the tool does.",
        mitigation="Describe the tool and each parameter; constrain strings with enum/pattern/maxLength; "
        "set `additionalProperties: false`.",
        limitations="Cannot see the server's own validation; a constrained-looking schema can still be "
        "unsafe and a loose one can be validated server-side.",
        references=(REF_TOOLS, REF_OWASP_MCP05),
        standards=(CWE_20, CWE_1059, OWASP_MCP05, OWASP_LLM06),
        detection="Missing/short description; missing inputSchema; open object; free-form string "
        "parameter named command/cmd/shell/script/sql/query/path/url/code without constraints (Medium).",
    )
)
_add(
    RuleMeta(
        id="TOOL-007",
        title="Tool name collision or look-alike across servers",
        threat="T3",
        property="A tool name maps to one server (spec: uniqueness is per server; aggregating clients "
        "SHOULD disambiguate).",
        kind=Kind.INDICATOR,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        impact="When two servers expose `search`, or one exposes `send_message` and another "
        "`send-message`, the model may call the wrong one — the shadowing vector used to redirect "
        "messages in published PoCs.",
        mitigation="Use a client that prefixes tool names per server; avoid connecting servers with "
        "overlapping tool names in one session.",
        limitations="Needs more than one catalogue in the scan. Generic verbs (`search`) collide "
        "innocently; the finding says which servers are involved.",
        references=(REF_TOOLS_NAMES, REF_INVARIANT),
        standards=(CWE_694, CWE_451, OWASP_MCP03, OWASP_MCP09),
        detection="Exact duplicates across catalogues with different server labels (High); normalised "
        "or confusable-character matches (Medium); duplicates within one catalogue (Low).",
    )
)
_add(
    RuleMeta(
        id="TOOL-008",
        title="Untrusted-content ingress and side-effect tools in one catalogue",
        threat="T4",
        property="Content retrieved by a tool is data, not instructions (not enforceable by the "
        "protocol; spec: clients SHOULD validate results).",
        kind=Kind.INFO,
        severity=Severity.INFO,
        confidence=Confidence.MEDIUM,
        impact="Indirect prompt injection needs an ingress (a tool that reads web pages, issues, mail) "
        "and a sink (a tool that writes, sends, or executes). Listing both makes the chain visible.",
        mitigation="Keep ingress and sink tools in separate sessions where possible; require "
        "confirmation on sink tools; sanitise retrieved content.",
        limitations="Surface enumeration only. Static analysis cannot detect prompt injection.",
        references=(REF_TOOLS_SECURITY, REF_INVARIANT),
        standards=(CWE_1427, CWE_250, OWASP_MCP06, OWASP_MCP10, OWASP_LLM01, OWASP_LLM06),
        detection="`openWorldHint: true` or fetch/search/mail vocabulary → ingress; exec/write/send "
        "vocabulary → sink. One Info finding per catalogue when an ingress tool exists.",
    )
)
_add(
    RuleMeta(
        id="TOOL-009",
        title="Invalid x-mcp-header annotation",
        threat="T9",
        property="`x-mcp-header` values satisfy the specification's constraints.",
        kind=Kind.WEAKNESS,
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        impact="Conforming clients MUST reject the whole tool; non-conforming clients may mirror "
        "unexpected values into headers, where routing or policy decisions are made on them.",
        mitigation="Use a valid HTTP token name, unique per schema, on primitive statically reachable "
        "properties only.",
        limitations="Checks the schema text only.",
        references=(REF_TOOLS_XHEADER,),
        standards=(CWE_20, OWASP_MCP01),
        spec_note="MCP 2026-07-28.",
        detection="Empty/non-token names; duplicates (case-insensitive); non-primitive or `number` "
        "types; placement under items/oneOf/anyOf/allOf/not/if/then/else/$ref.",
    )
)

# --------------------------------------------------------------------------- package-code rules
# These read the server's code from a local launcher cache or script path (docs/design.md §8).
# They never run it and never fetch it.

_add(
    RuleMeta(
        id="CFG-018",
        title="Install-time hook in the launched package",
        threat="T6",
        property="Code the package runs happens only when the server runs, not when the launcher "
        "installs or updates it.",
        kind=Kind.INDICATOR,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        impact="`preinstall`, `install` and `postinstall` scripts execute with the user's "
        "privileges the moment `npx`/`bunx`/`pnpm dlx` resolves the package — before any tool is "
        "listed, before any approval prompt, and on every silent update of an unpinned package. "
        "This is the mechanism behind most published npm supply-chain payloads.",
        mitigation="Pin the package (CFG-001) and read the hook script before approving. Prefer "
        "packages without install hooks, or install with `--ignore-scripts` and launch from a local "
        "checkout.",
        limitations="Reads `package.json` scripts and a `setup.py` `cmdclass` only; hooks in "
        "transitive dependencies and in wheels' build backends are not seen. A hook is a signal, "
        "not a verdict: native-addon builds use them legitimately.",
        references=(REF_NPM_SCRIPTS, REF_LOCAL_COMPROMISE, REF_OWASP_MCP04),
        standards=(CWE_829, CWE_506, OWASP_MCP04, OWASP_LLM03),
        detection="The located package's `package.json` has a `preinstall`/`install`/`postinstall` "
        "script, or its `setup.py` defines `cmdclass`. `prepare` is ignored (npm runs it for "
        "checkouts and git dependencies, not for registry installs).",
    )
)
_add(
    RuleMeta(
        id="CFG-019",
        title="Launched package can fetch and execute code at runtime",
        threat="T6",
        property="The code that runs is the code that was reviewed: the package does not evaluate "
        "strings it obtained at runtime.",
        kind=Kind.INDICATOR,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        impact="A package that both reaches the network and evaluates code (`eval`, `new Function`, "
        "`vm.runIn*`, Python `exec`/`eval`, `pickle.loads`) can change behaviour after review "
        "without any change to its version, catalogue or files on disk.",
        mitigation="Review every dynamic-evaluation site; prefer packages that do not evaluate "
        "runtime strings. Lock the package (`mcp-trustcheck lock`) so that at least the on-disk "
        "code cannot change silently.",
        limitations="Co-occurrence in one package, not a proven data flow from the network to the "
        "evaluator. Bundlers and plugin loaders use dynamic imports legitimately; those are "
        "recorded in the manifest but do not trigger this rule.",
        references=(REF_LOCAL_COMPROMISE, REF_OWASP_MCP04),
        standards=(CWE_94, CWE_494, OWASP_MCP04, OWASP_MCP05),
        detection="Manifest contains a strong `dynamic_code` sink (not a plain `import()`/`require()`"
        "/`import_module`) and a `network` sink: Medium. Strong dynamic sink alone: Low.",
    )
)
_add(
    RuleMeta(
        id="CFG-020",
        title="Launched package or its capabilities drifted from the lock",
        threat="T2",
        property="What the client launches today is what was reviewed when the lock was written: "
        "same package version and content, no new capability class, no new install hook.",
        kind=Kind.INDICATOR,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        impact="An unpinned or re-published package can gain the ability to run programs, write "
        "files or reach new hosts with no change to the config file. Catalogue drift (TOOL-006) "
        "would miss it when the tool descriptions stay the same.",
        mitigation="Re-review the package, then re-run `mcp-trustcheck lock` to accept the new "
        "state. Pin the version in the config (CFG-001).",
        limitations="Only runs with `--lock`. Compares against the lock's recorded version, content "
        "digest and capability classes; a change inside an already-present class (a different "
        "host, a different file) is reported at lower severity as part of the digest change.",
        references=(REF_CSA, REF_OWASP_MCP04, REF_LOCAL_COMPROMISE),
        standards=(CWE_345, CWE_494, OWASP_MCP04, OWASP_MCP03, OWASP_LLM03),
        detection="Per server in the lock: version changed (Medium); same version but content "
        "digest changed (High); new capability class at package or tool level, or new install "
        "hook (High); launch line changed, or server absent from the lock (Medium); locked package "
        "no longer locatable (Low).",
    )
)
_add(
    RuleMeta(
        id="CFG-021",
        title="Tool handler can read credentials and reach the network",
        threat="T9",
        property="A tool's implementation touches only the credentials of the service it exists to "
        "talk to, and sends them only to that service.",
        kind=Kind.INDICATOR,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        impact="A handler that reads SSH keys, cloud credential files, another MCP client's config "
        "or a third-party API token and also reaches the network has the exact shape of an "
        "exfiltration payload. Every tool call the user approves for its stated purpose is then "
        "also an opportunity to ship those secrets off the machine.",
        mitigation="Read the handler and every helper it calls at the file:line given. If the "
        "credential read is not needed for the tool's purpose, treat the package as hostile: "
        "remove it, rotate the credentials it could reach, and report it. If it is needed (a backup "
        "tool, a credential manager), lock the package so the behaviour cannot change silently.",
        limitations="Static reachability in the package's own code: a read behind a condition or in "
        "a helper shared with an honest tool is still reported. Paths assembled at runtime from "
        "pieces on different lines, secrets read through a library wrapper, and hosts not written "
        "as literals are not seen. The service-to-host table is short; a secret the table does not "
        "know is not judged.",
        references=(REF_LOCAL_COMPROMISE, REF_TOKEN_PASSTHROUGH, REF_OWASP_MCP03),
        standards=(CWE_200, CWE_522, CWE_506, OWASP_MCP01, OWASP_MCP03, OWASP_LLM02),
        detection="Per attributed tool handler: a `fs_read` sink whose path names a credential "
        "store (`~/.ssh`, `~/.aws/credentials`, `.netrc`, `.npmrc`, browser login stores, "
        "`.claude.json`, `claude_desktop_config.json`, …) together with any `network` sink: High. "
        "An `env` sink naming a known third-party secret (`AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, "
        "`OPENAI_API_KEY`, …) together with a network sink whose literal host the owning service "
        "does not control: Medium; with no literal host at all: Medium at one confidence step "
        "lower. Confidence follows attribution (AST High, lexical Medium, minified Low). When no "
        "handler could be attributed the same test runs over the whole package, one severity "
        "step lower.",
    )
)
_add(
    RuleMeta(
        id="TOOL-012",
        title="Declared behaviour contradicts the handler's code",
        threat="T1",
        property="A tool's catalogue entry (annotations, name, description) is consistent with what "
        "its implementation can do.",
        kind=Kind.WEAKNESS,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        impact="Clients and users decide whether to approve a call from the catalogue entry. A tool "
        "presented as read-only whose handler can run programs or delete files turns that approval "
        "into an unreviewed grant; the catalogue text can be worded to pass every keyword scanner.",
        mitigation="Fix the annotation (`readOnlyHint`/`destructiveHint`) or rename and re-describe "
        "the tool so that it says what the code does. Treat the tool as side-effecting until then.",
        limitations="Static reachability, not a proof of execution: the sink may sit behind a "
        "condition, be dead code, or be reached only with specific arguments. Confidence is High "
        "for Python (AST attribution), Medium for JavaScript/TypeScript (lexical ranges), and Low "
        "when the file is minified. Tools whose handler could not be attributed are not judged.",
        references=(REF_TOOLS_ANNOTATIONS, REF_TOOLS_UI, REF_INVARIANT),
        standards=(CWE_451, CWE_250, OWASP_MCP03, OWASP_MCP02, OWASP_LLM06),
        detection="Match catalogue to manifest by server name. `readOnlyHint: true` and the handler "
        "reaches exec/fs_write/fs_delete: High. Read-looking tool (get/list/read/search/fetch "
        "vocabulary, no write/exec/delete/send vocabulary) reaching exec or fs_delete: Medium; "
        "reaching fs_write only: Low.",
    )
)


def get(rule_id: str) -> RuleMeta:
    try:
        return RULES[rule_id]
    except KeyError as exc:  # pragma: no cover - programming error
        raise KeyError(f"unknown rule {rule_id}") from exc


def all_rule_ids() -> list[str]:
    return sorted(RULES)
