# MCP Security Threat Model (Phase 1)

**Project:** mcp-trustcheck — static security analysis for Model Context Protocol deployments
**Status:** Draft for review, 2026-10-23
**Spec baseline:** MCP `2026-07-28` (current), with notes for `2025-11-25` and `2025-06-18` where behaviour differs

This document defines what `mcp-trustcheck` tries to find, why each finding matters, and what it cannot establish. Every proposed check in §6 maps back to a trust boundary (§2), a threat (§3), and a documented security property or an explicitly stated hypothesis.

---

## 1. Scope and protocol-version assumptions

### 1.1 What the tool analyses

`mcp-trustcheck` performs **read-only static analysis** of artefacts a developer already has on disk:

| Artefact | Typical source | Format |
|---|---|---|
| Client-side server configuration | `claude_desktop_config.json`, `.cursor/mcp.json`, `.mcp.json`, `.vscode/mcp.json` | JSON, `mcpServers` / `servers` object |
| Tool catalogue snapshot | A saved `tools/list` result, or an array of Tool objects exported from an SDK | JSON |
| (Optional) trusted baseline | A previously approved tool catalogue | JSON |

Config file formats are **not** part of the MCP specification; they are client conventions. The tool therefore treats the common `mcpServers` shape (`command`, `args`, `env`, `url`, `headers`, `type`) as a de facto dialect and documents which keys it understands. Server-side framework configs (FastMCP settings, Docker Compose, etc.) are out of scope for the MVP.

### 1.2 Protocol versions

The current revision is `2026-07-28`. It is a breaking change: the protocol core is stateless, `initialize`/`initialized` and `Mcp-Session-Id` are removed, every request carries its version and client capabilities in `_meta`, and Streamable HTTP requests must carry `Mcp-Method` / `Mcp-Name` headers. Server-to-client requests (elicitation, sampling, roots) became Multi Round-Trip Requests (MRTR). The legacy HTTP+SSE transport (2024-11-05) is formally deprecated.

Version-dependent facts that matter for this threat model:

| Topic | `2025-06-18` / `2025-11-25` | `2026-07-28` |
|---|---|---|
| Sessions | Server-assigned `Mcp-Session-Id`; session hijacking is a documented attack | No protocol sessions; replaced by explicit *state handles* passed as tool arguments, with a new "state handle hijacking" attack class |
| Tool list changes | `notifications/tools/list_changed` on a GET SSE stream | Same notification, but only on an opt-in `subscriptions/listen` stream; `tools/list` results carry `ttlMs` / `cacheScope` |
| Tool annotations | `readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint` (introduced 2025-03-26); clients MUST treat as untrusted unless from a trusted server | Unchanged |
| `x-mcp-header` | Not present | Tool parameters can be mirrored into HTTP headers; servers SHOULD NOT mark sensitive parameters |
| Authorization | OAuth 2.1 resource server model; PRM (RFC 9728) and resource indicators (RFC 8707) mandatory for clients | Adds RFC 9207 `iss` validation (mix-up defence), issuer-bound client credentials, DCR deprecated in favour of Client ID Metadata Documents (CIMD) |
| Origin validation | MUST validate `Origin`, SHOULD bind localhost | Unchanged |

Where a check's rationale depends on a specific revision, the finding records that revision.

---

## 2. Architecture and trust boundaries

```
 ┌────────────┐   B1    ┌──────────────┐   B2    ┌─────────────┐   B4    ┌───────────────┐
 │   User     │◄──────► │  MCP Host /  │◄──────► │  MCP Server │◄──────► │ External API  │
 │            │         │  Client (+LLM)│  stdio  │ (local or   │  HTTP   │ / 3rd-party   │
 └────────────┘         └──────┬───────┘  /HTTP   │  remote)    │         │ AuthZ server  │
                               │ B3              └──────┬──────┘         └───────────────┘
                               ▼                        │ B5
                        ┌──────────────┐                ▼
                        │ Tool outputs,│         ┌─────────────┐
                        │ resources,   │         │ Host OS:    │
                        │ web content  │         │ files, shell│
                        └──────────────┘         │ env, network│
                                                 └─────────────┘
                                 B6: other MCP servers connected to the same client
```

| Boundary | Between | Why it matters |
|---|---|---|
| **B1** User ↔ Host/Client | Human consent and the LLM | The spec says there SHOULD always be a human able to deny tool calls; clients SHOULD show inputs before calling. Auto-approval settings weaken this. |
| **B2** Client ↔ Server | Protocol transport (stdio or Streamable HTTP) | Everything a server sends (tool names, descriptions, schemas, annotations, results) is attacker-controlled if the server is. The spec is explicit that annotations are untrusted unless the server is trusted. |
| **B3** Client ↔ Content | Tool results and resources entering model context | Untrusted content becomes instructions to the model. This is an LLM-level boundary the protocol cannot enforce. |
| **B4** Server ↔ Upstream | OAuth, API keys, downstream APIs | Confused deputy, token passthrough, SSRF via metadata URLs, scope inflation. |
| **B5** Server ↔ Host OS | Process privileges, filesystem, shell | Local servers run with the client's privileges; command injection in tool implementations (CWE-77/78) has produced many CVEs. |
| **B6** Server ↔ Server | Multiple servers in one client | Tool shadowing and name collision; one malicious server can influence calls to another. |

**Local vs. remote matters.** A stdio server has no network surface; its boundary is the process. A Streamable HTTP server has an `Origin`/DNS-rebinding surface, an authentication surface, and (if it proxies) a confused-deputy surface. The same finding (e.g., missing auth) has different meaning in each case, and the tool must not assume one architecture.

---

## 3. Threats

Each threat lists the **security property** at stake, **preconditions**, the **layer** (P = protocol-level, A = application/implementation, L = general LLM/agent risk), and primary references. Layer tags are important: the toolkit can only make strong claims about P-layer violations; A-layer findings are implementation indicators; L-layer risks are documented, not detected.

### T1 — Tool poisoning (malicious tool metadata)
- **Property:** Tool metadata should describe behaviour, not instruct the agent.
- **Threat:** Instructions hidden in `description`, parameter descriptions, titles, enum values or defaults steer the model to read secrets, exfiltrate data, or alter other tool calls. Later research showed every schema field, not just `description`, is a carrier.
- **Preconditions:** A server the user installs or is tricked into installing; a client that passes metadata verbatim to the model (normal behaviour); the model follows the embedded instruction.
- **Layer:** P (the protocol delivers untrusted metadata into context by design) + L (whether the model obeys).
- **Boundary:** B2, B3.
- **Refs:** Invariant Labs disclosure (Apr 2025); OWASP MCP Top 10 MCP03 (beta); CSA tool-poisoning whitepaper (May 2026); MCPTox benchmark (arXiv, Aug 2025) reporting >70% attack success against some models.

### T2 — Rug pull / post-approval drift
- **Property:** What the user approved is what runs.
- **Threat:** A server returns benign definitions at review time, then changes them. In `2026-07-28` the vector is unchanged in substance: `tools/list` MAY change over time; clients subscribed via `subscriptions/listen` get `list_changed`; clients that cache by `ttlMs` re-fetch silently.
- **Preconditions:** Point-in-time approval with no re-verification; a server (or its hosting) controlled or compromised after approval.
- **Layer:** P (the protocol explicitly allows the set to change) + A (client approval UX).
- **Boundary:** B1, B2.
- **Refs:** Invariant Labs (Apr 2025); CSA (2026); MCP tools spec §Capabilities.

### T3 — Cross-server tool shadowing and name collision
- **Property:** A tool call reaches the server the user intends.
- **Threat:** Tool names are only unique *within* a server; the spec notes aggregators MAY see collisions and SHOULD disambiguate. A malicious server can register a same-named or look-alike tool, or embed instructions that modify how another server's tool is called (e.g., changing a message recipient).
- **Preconditions:** ≥2 servers in one client; weak or absent disambiguation.
- **Layer:** P (no cross-server namespace) + A (client disambiguation).
- **Boundary:** B6.
- **Refs:** MCP tools spec §Tool Names; Invariant Labs WhatsApp PoC.

### T4 — Indirect prompt injection via tool output / external content
- **Property:** Content retrieved by a tool is data, not instructions.
- **Threat:** A GitHub issue, web page, email, or git log contains instructions the model follows, chaining into other tools (including ones with command-injection bugs — see T7).
- **Preconditions:** An open-world tool (`openWorldHint: true` or equivalent) whose output enters context; a downstream tool with side effects.
- **Layer:** L. The protocol cannot fix this; the spec only says servers MUST sanitise outputs and clients SHOULD validate results.
- **Boundary:** B3.
- **Refs:** Invariant Labs GitHub MCP PoC (May 2025); GHSA-3q26-f695-pp76 (injection via git logs leading to command injection).
- **Detectability:** Not detectable statically. The toolkit can only flag *ingress surfaces* (tools that import untrusted content) and *sinks* (tools with side effects) so a reviewer sees the chain.

### T5 — Excessive permissions and capability
- **Property:** Least privilege for the server process and for OAuth scopes.
- **Threat:** Filesystem server rooted at `/` or `$HOME`; Docker servers with `--privileged`, the Docker socket mounted, or `--network host`; broad OAuth scopes (`*`, `admin:*`) granted up front.
- **Preconditions:** Over-broad config plus any of T1/T2/T4.
- **Layer:** A (config) + P (scope guidance in security best practices).
- **Boundary:** B5, B4.
- **Refs:** MCP Security Best Practices §Scope Minimization; §Local MCP Server Compromise (clients SHOULD sandbox and restrict filesystem/network).

### T6 — Unsafe local execution and supply chain
- **Property:** The command that launches a server is known, pinned, and reviewed.
- **Threat:** A config entry is itself a command line executed with the user's privileges. `npx -y <unpinned package>` or `uvx <package>` resolves at launch; typosquatting or a compromised package is arbitrary code execution. Shell wrappers (`sh -c "…"`) and shell metacharacters in args enable obfuscation. Env variables such as `NODE_OPTIONS`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `PYTHONPATH` can inject code into the server process.
- **Preconditions:** One-click or copy-paste install; no review of the exact command (the spec says clients MUST show the full command and SHOULD highlight dangerous patterns).
- **Layer:** A, with spec-backed client requirements.
- **Boundary:** B5, B1.
- **Refs:** MCP Security Best Practices §Local MCP Server Compromise; CSA whitepaper §Supply chain.

### T7 — Command / argument injection in tool implementations
- **Property:** Tool arguments never reach a shell or a CLI flag position unvalidated.
- **Threat:** Server code builds shell strings from arguments (CWE-77/78) or passes them where a CLI interprets flags (argument injection). Triggerable by T4 without any user error.
- **Preconditions:** A vulnerable implementation plus a path for attacker-controlled arguments (prompt injection or a malicious client).
- **Layer:** A.
- **Boundary:** B5.
- **Refs:** CVE-2025-53107 (`@cyanheads/git-mcp-server`), CVE-2025-53967 (Framelink Figma MCP), CVE-2025-5277 / CVE-2026-5059 (aws-mcp-server), CVE-2026-25546 (godot-mcp), CVE-2025-68143..68145 (Anthropic `mcp-server-git`, path validation / argument injection); OWASP MCP05.
- **Detectability:** Not detectable from config or tool definitions. The toolkit can only flag tool *schemas* that expose free-form `command`/`path`/`query` strings as a surface to review. Source-level detection is a documented future enhancement.

### T8 — Improper authentication/authorization on remote servers
- **Property:** Tokens are issued to and validated by the right resource; only the intended principal reaches the server.
- **Threat:**
  - **Token passthrough** (server forwards client tokens downstream) — explicitly forbidden; servers MUST NOT accept tokens not issued to them.
  - **Confused deputy** in OAuth proxies using a static upstream client ID without per-client consent.
  - **Mix-up attacks** — mitigated in `2026-07-28` by `iss` validation (RFC 9207).
  - **SSRF** via attacker-controlled metadata URLs during discovery.
  - **State handle hijacking** (`2026-07-28`): treating possession of a handle as authentication.
  - **Session hijacking** (`≤2025-11-25`): predictable or unbound `Mcp-Session-Id`.
- **Preconditions:** A remote (HTTP) server; depends on sub-case.
- **Layer:** P (normative MUSTs in the authorization spec and security best practices).
- **Boundary:** B2, B4.
- **Detectability:** Mostly requires server source or live behaviour. From client config alone the toolkit can detect: plaintext `http://` to non-loopback hosts, static bearer tokens in headers, and hosts that look like loopback-only servers exposed remotely. Everything else is a documented future dynamic check.

### T9 — Credential and sensitive-data exposure
- **Property:** Secrets are not stored in plaintext config or transmitted on observable channels.
- **Threat:** API keys in `env` or `headers`; tokens in URLs; `x-mcp-header` on a sensitive parameter (header values are visible to intermediaries); config files committed to repos or synced.
- **Preconditions:** Plaintext config; any reader of the file or the network path.
- **Layer:** A, with one P-layer SHOULD NOT (`x-mcp-header`).
- **Boundary:** B2, B4, B5.
- **Refs:** MCP tools spec §x-mcp-header warning.

### T10 — Insecure transport and network exposure
- **Property:** Local servers are reachable only by the local client; remote servers use TLS and validate `Origin`.
- **Threat:** HTTP server bound to `0.0.0.0`; missing `Origin` validation → DNS rebinding from a web page to a local server; deprecated HTTP+SSE transport; `http://` to a remote host.
- **Preconditions:** HTTP transport; local server left running.
- **Layer:** P (MUST validate `Origin`; SHOULD bind localhost; SHOULD authenticate).
- **Boundary:** B2.
- **Refs:** Streamable HTTP spec §Security & Endpoint; CVE-2025-49596 (MCP Inspector) and CVE-2026-23744 (MCPJam inspector) as exposure examples.

### T11 — Weakened human-in-the-loop
- **Property:** A human can see and deny tool invocations.
- **Threat:** Client-specific auto-approve / "always allow" / trust flags remove the consent step the spec recommends, which multiplies the impact of T1, T2 and T4 (poisoning success rates are reported to be highest under auto-approval).
- **Layer:** A (client feature) grounded in a P-layer SHOULD.
- **Boundary:** B1.
- **Refs:** MCP tools spec §User Interaction Model.

---

## 4. Protocol vs. application vs. LLM — classification summary

| Threat | Protocol-level | Application-level | LLM/agent-level | Statically detectable? |
|---|---|---|---|---|
| T1 Tool poisoning | ✔ delivery channel | — | ✔ compliance | Partially (indicators) |
| T2 Rug pull | ✔ allowed by design | ✔ approval UX | — | Yes, *given a baseline* |
| T3 Shadowing/collision | ✔ no global namespace | ✔ disambiguation | ✔ | Partially |
| T4 Indirect injection | — | — | ✔ | No (surfaces only) |
| T5 Excess permission | ✔ scope guidance | ✔ | — | Yes (config) |
| T6 Unsafe local exec | ✔ consent MUSTs | ✔ | — | Yes (config) |
| T7 Command injection | — | ✔ | — | No (surfaces only) |
| T8 AuthN/AuthZ | ✔ | ✔ | — | Limited (config) |
| T9 Secret exposure | ✔ (x-mcp-header) | ✔ | — | Yes |
| T10 Transport | ✔ | ✔ | — | Yes (config) |
| T11 Human-in-loop | ✔ (SHOULD) | ✔ | — | Yes (client keys) |

---

## 5. Severity and confidence model

Severity and confidence are **separate axes** and neither is a numeric score.

**Severity** = the realistic impact *if the finding is true*, by consequence class:

| Severity | Consequence class |
|---|---|
| Critical | Arbitrary code execution with user privileges, or disclosure of a credential that grants broad access |
| High | Likely data exfiltration, credential disclosure with limited scope, or a normative MUST/MUST NOT violation with direct exploit path |
| Medium | Materially weakened security property (least privilege, consent, transport) that needs a second condition to exploit |
| Low | Hygiene / defence-in-depth gap |
| Info | Surface worth knowing about; no weakness asserted |

**Confidence** = how deterministic the detection is:

| Confidence | Meaning |
|---|---|
| High | Exact match against a documented rule (e.g., `http://` to non-loopback host; `x-mcp-header` on a parameter named `password`; baseline hash mismatch) |
| Medium | Strong structural signal with known benign cases (e.g., `npx -y` unpinned; filesystem root `~`) |
| Low | Heuristic / lexical indicator (e.g., imperative language in a description) |

Every finding states whether it is a **configuration weakness** (a property is not met) or an **indicator** (needs human review). No finding is labelled a "vulnerability" unless it is a known-exploitable class with a direct path (e.g., a disclosed live secret).

---

## 6. Proposed checks

**MVP** checks are those the Phase 3 scanner will implement. **Future** checks are documented so the design accommodates them. For each MVP check the Phase 2 design will add a synthetic positive and negative fixture.

### 6.1 Configuration checks (`CFG-*`)

| ID | Title | Threat | Property / reference | Detection logic (contextual) | Severity | Conf. | Known FP / FN | MVP |
|---|---|---|---|---|---|---|---|---|
| CFG-001 | Unpinned package execution | T6 | Best Practices §Local Server Compromise | `command` ∈ {`npx`,`uvx`,`pipx run`,`bunx`,`dlx`} with a package arg lacking an exact version. Scoped packages and git URLs scored separately. | Medium | Medium | FP: deliberate "latest" in dev. FN: lockfiles outside config. | ✔ |
| CFG-002 | Unexpected or suspicious executable | T6 | same | Executable path under temp/downloads/cache dirs, non-absolute path that is not a known launcher, or binary name mismatching package name. | Medium | Low–Med | FP: custom dev wrappers. | ✔ |
| CFG-003 | Shell-mediated execution | T6 | same (clients SHOULD highlight dangerous patterns) | `command` is a shell (`sh`,`bash`,`zsh`,`cmd`,`powershell`,`pwsh`) with `-c`/`/c`; **or** any arg contains metacharacters (`&&`, `;`, `|`, `$(`, backtick, `>`) *and* the command is a shell. Metacharacters in argv for a non-shell command are reported Info only, because most clients spawn without a shell. | High / Info | High | FN: shell invoked by a wrapper script. | ✔ |
| CFG-004 | Dangerous command content | T6 | same (explicit examples: `sudo`, `rm -rf`, `curl … \| sh`, SSH key paths) | Pattern match within the resolved command line for privilege escalation, destructive, or download-and-execute idioms; sensitive paths (`~/.ssh`, `~/.aws`, keychains). | Critical/High | High | FP: legitimate maintenance scripts. | ✔ |
| CFG-005 | Hardcoded secret | T9 | OWASP secrets guidance; Best Practices §Token Passthrough (static tokens) | Known-prefix detectors (e.g., `sk-`, `ghp_`, `AKIA`, `xox`) plus Shannon-entropy test on `env` values, `headers` values, and URL query/userinfo. **Negative:** `${env:…}`, `${input:…}`, `${VAR}`, VS Code `inputs` refs, empty/placeholder values. Output is always redacted (`sk-…[redacted 48 chars]`). | High (Critical if cloud root key) | High (prefix) / Medium (entropy) | FP: random non-secret IDs. FN: low-entropy passwords. | ✔ |
| CFG-006 | Over-broad filesystem access | T5 | Best Practices (restrict FS access to expected dirs) | Recognise filesystem-type servers (known package names or `--root`/`--allowed-dir` style args); flag roots of `/`, `C:\`, `~`, `$HOME`, `/Users`, `/home`, or a parent of the config's own directory. Also Docker `-v /:/…`. | Medium (High for `/`) | Medium | FP: intentional whole-disk access. FN: unrecognised server exposes paths differently. | ✔ |
| CFG-007 | Privileged container launch | T5, T6 | Best Practices (sandbox with minimal privileges) | `docker run` / `podman run` with `--privileged`, `--network host`, `--pid host`, `-v /var/run/docker.sock`, `--cap-add SYS_ADMIN`, running as root explicitly. | High | High | FP: tooling that needs it (rare). | ✔ |
| CFG-008 | Code-injection environment variables | T6 | — (hypothesis: these vars alter process behaviour at load time) | `env` sets `NODE_OPTIONS`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_*`, `PYTHONPATH`, `PYTHONSTARTUP`, `PERL5OPT`, `RUBYOPT`. | Medium | Medium | FP: legitimate module paths. | ✔ |
| CFG-009 | Plaintext remote transport | T10 | Streamable HTTP §Security; OAuth 2.1 (TLS required) | `url` scheme `http://` or `ws://` where host is not loopback (`localhost`, `127.0.0.0/8`, `::1`). Severity rises to High if `headers` contains `Authorization`. | Medium / High | High | FP: trusted LAN / tunnel. | ✔ |
| CFG-010 | Deprecated transport | T10 | Streamable HTTP §Backward Compat; deprecated features registry | `type: "sse"` or URL path/`transport` indicating legacy HTTP+SSE. Finding notes it is deprecated since 2025-03-26 with removal eligibility. | Low | High | — | ✔ |
| CFG-011 | Network-exposed local server | T10 | Streamable HTTP §Security (SHOULD bind localhost) | Args/env that bind a local HTTP server to `0.0.0.0`, `::`, or a non-loopback interface (`--host`, `HOST`, `FASTMCP_HOST`, `MCP_HOST`, `--bind`). | Medium (High if no auth signal) | Medium | FP: container networking where 0.0.0.0 is required; the finding says so. | ✔ |
| CFG-012 | Remote server without auth signal | T8 | Authorization spec (optional at protocol level; servers SHOULD authenticate) | `url` to non-loopback host with no `headers`, no `oauth`/`auth` key, and no client-specific auth hint. Reported as **Info** because the client may perform OAuth discovery at runtime. | Info | Low | FP: OAuth discovery; public read-only servers. | ✔ |
| CFG-013 | Consent / approval weakened | T11 | Tools spec §User Interaction Model (SHOULD keep human in loop) | Client-specific keys: `autoApprove`, `alwaysAllow`, `trust: true`, `disabledTools` inverse, `auto_approve_all`. Reported per server with the list of auto-approved tools. | Medium (High if wildcard) | High (key match) | FN: approval configured outside the file. | ✔ |
| CFG-014 | Duplicate server names / shadowed entries | T3 | Tools spec §Tool Names note | Same server key across multiple scanned config files (e.g., project `.mcp.json` overriding user config) or two entries launching the same package. | Low | High | — | ✔ |
| CFG-015 | Secret in `x-mcp-header` parameter | T9 | Tools spec §x-mcp-header (SHOULD NOT) — `2026-07-28` only | In a tool definition, `x-mcp-header` on a property whose name/description matches secret vocabulary (`token`, `password`, `api_key`, `secret`, `ssn`, `email`). | High | High | FP: a parameter literally named "token" for a non-secret. | ✔ (tool file) |
| CFG-016 | Config file permissions / location | T9 | — | World-readable config containing CFG-005 hits; config inside a git working tree without `.gitignore` coverage. | Low–Medium | Medium | Platform-specific; Windows ACLs not evaluated. | Future |
| CFG-017 | OAuth proxy / token-passthrough patterns | T8 | Best Practices §Confused Deputy, §Token Passthrough | Requires server source or live probing. | — | — | — | Future (dynamic, opt-in) |
| CFG-018 | Install-time hook in the launched package | T6 | npm lifecycle scripts; OWASP MCP04 | The package the launcher resolves (read from the local `npx`/`bunx`/`pnpm dlx`/`uvx`/`pipx` cache or the script path, never fetched) declares `preinstall`/`install`/`postinstall`, or a `setup.py` `cmdclass`. | Medium | High | FP: native-addon builds. FN: hooks in transitive dependencies. | ✔ (0.2) |
| CFG-019 | Launched package can fetch and execute code at runtime | T6 | OWASP MCP04, MCP05 | Capability manifest of the package contains a strong dynamic-evaluation sink (`eval`, `new Function`, `vm.runIn*`, Python `exec`/`eval`, `pickle.loads`) and a network sink. | Medium / Low | Medium | FP: plugin loaders over trusted code. FN: indirection the analyser does not follow. | ✔ (0.2) |
| CFG-020 | Package or capability drift against the lock | T2 | CSA rug-pull guidance; OWASP MCP04 | `mcp-trustcheck lock` records version, content digest, capability classes (package and per tool), install hooks and the approved catalogue per server; `verify` reports version change, same-version content change, new capability class, new tool, new hook, changed launch line, server absent from lock. | High / Medium | High | FP: legitimate upgrades (re-review, re-lock). | ✔ (0.2, `--lock`) |
| CFG-021 | Tool handler can read credentials and reach the network | T9 | Best Practices §Local MCP Server Compromise, §Token Passthrough; OWASP MCP01, MCP03 | Per attributed tool handler in the package manifest: a file read whose literal path (or source line) names a credential store (`~/.ssh`, `~/.aws/credentials`, `.netrc`, `.npmrc`, browser login stores, `.claude.json`, `claude_desktop_config.json`, …) plus any network sink → High; an environment read of a known third-party secret (`AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `OPENAI_API_KEY`, …) plus a network sink to a host that service does not own → Medium (no literal host: Medium, confidence one step lower). No attributed handler: same test over the whole package, one severity lower. | High / Medium | High (AST) / Medium (lexical) / Low (minified) | FP: backup and credential-manager tools, shared helpers, services missing from the host table. FN: paths assembled across lines, wrapper libraries, computed hosts, subprocess exfiltration. | ✔ (0.2) |

### 6.2 Tool and trust-boundary checks (`TOOL-*`)

| ID | Title | Threat | Property / reference | Detection logic | Severity | Conf. | Known FP / FN | MVP |
|---|---|---|---|---|---|---|---|---|
| TOOL-001 | Agent-directed instructions in metadata | T1 | Spec: annotations/descriptions untrusted; Invariant Labs | Lexical and structural signals across **all** string fields (description, title, parameter descriptions, enum values, defaults): second-person imperatives aimed at the model ("you must", "before calling", "ignore previous"), secrecy directives ("do not tell the user", "do not mention"), bracketed pseudo-tags (`<IMPORTANT>`, `[SYSTEM]`), file-path or URL references unrelated to the tool's stated purpose, and references to other tools. ≥2 independent signals → Medium confidence; 1 → Low. Never asserted as malicious. | High (if secrecy + exfil path) / Medium | Low–Med | FP: verbose legitimate docs. FN: paraphrased or multilingual payloads. | ✔ |
| TOOL-002 | Hidden or obfuscated content | T1 | same; CyberArk follow-up research | Zero-width / bidi / tag Unicode, excessive whitespace runs, HTML comments, long base64 or hex blobs, description length far above the server's median. | Medium | High (encoding) / Medium (length) | FP: emoji-heavy or RTL-language descriptions (handled by allowlisting scripts). | ✔ |
| TOOL-003 | Cross-server reference | T3 | Tools spec §Tool Names | Description names another tool or server not present in the same definition set, or uses "for all other tools / whenever X is called" phrasing. | Medium | Medium | FP: legitimate workflow hints. | ✔ |
| TOOL-004 | Annotation / behaviour mismatch | T1, T5 | Tools spec: annotations are hints and untrusted | Infer capability class from name, description and schema (exec/shell, FS write/delete, network send, payment) and compare with annotations: `readOnlyHint: true` on an apparent write → finding; `destructiveHint: false` on apparent delete → finding; no annotations on apparent-sensitive tool → Info (clients already must assume worst case). | Medium / Info | Medium | FP: naming ambiguity ("remove_filter"). | ✔ |
| TOOL-005 | Underspecified tool definition | T1, T7 | Tools spec (inputSchema MUST be valid object; descriptions for parameters) | Empty/very short description; `inputSchema` missing `properties` while not `additionalProperties: false`; free-form string parameters with no description; parameter named `command`/`cmd`/`shell`/`script`/`sql`/`path` with no constraints. | Low (Medium for free-form exec params) | High (structural) | FP: deliberately minimal tools. | ✔ |
| TOOL-006 | Baseline drift (rug-pull detection) | T2 | Tools spec: set MAY change; Invariant MCP-Scan pinning approach | Canonicalise each tool (name, description, inputSchema, outputSchema, annotations) → SHA-256; compare current snapshot with a user-supplied trusted baseline; report added, removed, and changed tools with a field-level diff. Works offline on two JSON files. | High | High | FP: legitimate updates (that is the point — the user must re-approve). | ✔ |
| TOOL-007 | Name collision / look-alike | T3 | Tools spec §Tool Names | Across all tool sets scanned: identical names from different servers; near-identical names (case, `_`/`-`, confusable characters). | Medium | High / Medium | FP: common verbs (`search`) — reported Info when both are from well-known packages. | ✔ |
| TOOL-008 | Untrusted-content ingress surface | T4 | Tools spec §Security Considerations (clients SHOULD validate results) | `openWorldHint: true`, or name/description indicating fetch/read of external content. **Info only** — lists these tools alongside side-effect tools so a reviewer can see injection → action chains. | Info | High | — | ✔ |
| TOOL-009 | Invalid `x-mcp-header` usage | T9 | Tools spec §x-mcp-header constraints — `2026-07-28` | Header name not a valid token, non-primitive type, duplicate names, not statically reachable. (Clients MUST reject these; a server shipping them is misconfigured.) | Low | High | — | ✔ |
| TOOL-010 | Live tool-list drift monitoring | T2 | — | Connect, snapshot, re-check periodically. Requires explicit authorisation and network access. | — | — | — | Future (dynamic, opt-in) |
| TOOL-011 | Source-level command injection | T7 | OWASP MCP05 | Taint-style analysis of server source. | — | — | — | Future |
| TOOL-012 | Declared behaviour contradicts the handler's code | T1 | Tools spec §Tool Annotations (hints, untrusted) | Catalogue matched to the package manifest by server label; per tool, the capability classes reachable from the handler (Python: AST, FastMCP/`call_tool` idioms; JS/TS: lexical ranges of `server.tool("name", …)`, `case "name":`, `if (name === "name")`) are compared with `readOnlyHint` and the name/description vocabulary. Read-only claim vs exec/write/delete reach → High; read-looking name vs exec/delete → Medium; vs write → Low. | High / Medium / Low | High (AST) / Medium (lexical) / Low (minified) | FP: dead or conditional sinks, shared helpers. FN: unattributed handlers, side effects in subprocesses. | ✔ (0.2) |

---

## 7. What this tool cannot establish

These statements will appear in the README and in each report:

1. **Static analysis cannot determine that a tool is malicious.** TOOL-001..005 are indicators. A clean result is not a safety guarantee; a hit is not proof of intent.
2. **It cannot detect indirect prompt injection** (T4) or whether a model will follow an instruction. It can only show which tools import untrusted content and which have side effects.
3. **It cannot verify server implementations** (T7, T8) without source or live access. A config that looks fine may launch a vulnerable server.
4. **Config dialects are client-specific.** Unknown keys are reported as unparsed, not assumed safe.
5. **Secret detection is heuristic.** Prefix matches are reliable; entropy matches are not.
6. **Version coverage:** rules are written against `2026-07-28` and note where `≤2025-11-25` behaviour differs. Clients and servers in the wild run mixed versions.

---

## 8. Decisions needed before Phase 2

1. **Licence** — *decided in Phase 6:* Apache-2.0.
2. **Config dialects for MVP** — proposal: the `mcpServers` object (Claude Desktop / Cursor / Claude Code `.mcp.json`) and VS Code `servers` + `inputs`. Others as future work.
3. **Tool snapshot input** — proposal: accept either a raw `tools/list` JSON-RPC result or a bare array of Tool objects, plus an optional `--baseline <file>` for TOOL-006.
4. **Package name** — *decided in Phase 6:* the working name `mcp-audit` collided with the command installed by the existing `mcp-audit-scanner` project, so the project publishes as `mcp-trustcheck` (free on PyPI as of 2026-11-02).

---

## 9. References

**Primary (normative)**
- MCP Specification 2026-07-28 — https://modelcontextprotocol.io/specification/2026-07-28
- Changelog 2026-07-28 — https://modelcontextprotocol.io/specification/2026-07-28/changelog
- Tools — https://modelcontextprotocol.io/specification/2026-07-28/server/tools
- Streamable HTTP transport — https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http
- Authorization — https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
- Security Best Practices (2026-07-28) — https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices
- Security Best Practices (2025-11-25, session hijacking) — https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices
- Release announcement — https://blog.modelcontextprotocol.io/posts/2026-07-28/
- RFC 8707 (Resource Indicators), RFC 9728 (Protected Resource Metadata), RFC 9207 (`iss`), RFC 9700 (OAuth security BCP)

**Research and advisories**
- Invariant Labs, "MCP Security Notification: Tool Poisoning Attacks" (Apr 2025) — https://invariantlabs.ai/blog/mcp-security-notification
- Cloud Security Alliance, "MCP Tool Poisoning and Rug Pull Attacks" (May 2026) — https://labs.cloudsecurityalliance.org/research-rb/csa-whitepaper-mcp-security-tool-poisoning-20260506-csa-styl/
- OWASP MCP Top 10 (beta): MCP03 Tool Poisoning, MCP05 Command Injection — https://owasp.org/www-project-mcp-top-10/
- GHSA-3q26-f695-pp76 / CVE-2025-53107 — https://github.com/advisories/GHSA-3q26-f695-pp76
- GHSA-6xpm-ggf7-wc3p / CVE-2025-6514 (mcp-remote) — https://github.com/advisories/GHSA-6xpm-ggf7-wc3p
- CVE-2025-53967 (Framelink Figma MCP), CVE-2025-5277 & CVE-2026-5059 (aws-mcp-server), CVE-2026-25546 (godot-mcp), CVE-2025-49596 (MCP Inspector), CVE-2026-23744 (MCPJam inspector), CVE-2025-68143/68144/68145 (mcp-server-git)
- MCPTox benchmark (arXiv 2508.xxxxx, Aug 2025) — cited via CSA; exact identifier to be confirmed in Phase 2 before it is quoted in the README.
