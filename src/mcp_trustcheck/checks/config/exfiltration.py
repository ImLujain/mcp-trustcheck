"""CFG-021: a tool handler that can read credentials and reach the network (threat-model.md T9).

Every API server reads its own key and calls its own API; that is not what this rule reports. It
looks for two shapes that have no place in a tool handler:

* a *credential file* read (`~/.ssh/*`, `~/.aws/credentials`, `.netrc`, `.npmrc`, browser profile
  stores, another MCP client's config, …) in a handler that also reaches the network, and
* a *third-party* secret taken from the environment (`AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`,
  `OPENAI_API_KEY`, …) in a handler that reaches a host the owning service does not control.

Reachability comes from the package manifest (docs/design.md §8); nothing is executed. A sink
behind a condition, or in a helper shared with an honest tool, still counts, which is why the
finding is an indicator and names every file and line it rests on.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from mcp_trustcheck.checks import Context, emit, register
from mcp_trustcheck.code.model import PHRASES, PackageManifest, Sink
from mcp_trustcheck.model import Affected, Confidence, Finding, ServerConfig, Severity

# Paths whose only sensible reader is the owner's own tooling. Matched against the sink's literal
# argument when the analyser captured one, otherwise against the source line.
CREDENTIAL_PATH_RE = re.compile(
    r"(?ix)"
    r"(?:^|[/\\\s\"'`$])(?:"
    r"\.ssh[/\\]|id_(?:rsa|dsa|ecdsa|ed25519)\b|known_hosts\b"
    r"|\.aws[/\\](?:credentials|config)\b|\.azure[/\\]|\.config[/\\]gcloud[/\\]"
    r"|\.kube[/\\]config\b|\.docker[/\\]config\.json\b"
    r"|\.netrc\b|_netrc\b|\.npmrc\b|\.pypirc\b|\.git-credentials\b|\.gnupg[/\\]"
    r"|\.config[/\\]gh[/\\]hosts\.yml\b|\.terraform\.d[/\\]credentials"
    r"|\.claude\.json\b|claude_desktop_config\.json\b|\.cursor[/\\]mcp\.json\b|\.codeium[/\\]"
    r"|Library[/\\]Keychains[/\\]|Login\s?Data\b|Cookies\b|Local\s?State\b|logins\.json\b|key4\.db\b"
    r"|\.bash_history\b|\.zsh_history\b|/etc/shadow\b"
    r"|\.wallet\b|wallet\.dat\b|\.bitcoin[/\\]|\.electrum[/\\]"
    r")"
)

# Environment variables that belong to a named third-party service, with the host suffixes that
# service controls. A handler that reads one and talks only to those hosts is doing its job.
SERVICE_ENV: dict[str, tuple[str, ...]] = {
    "AWS_SECRET_ACCESS_KEY": ("amazonaws.com", "aws.amazon.com"),
    "AWS_ACCESS_KEY_ID": ("amazonaws.com", "aws.amazon.com"),
    "AWS_SESSION_TOKEN": ("amazonaws.com", "aws.amazon.com"),
    "GITHUB_TOKEN": ("github.com", "githubusercontent.com"),
    "GH_TOKEN": ("github.com", "githubusercontent.com"),
    "GITHUB_PERSONAL_ACCESS_TOKEN": ("github.com", "githubusercontent.com"),
    "GITLAB_TOKEN": ("gitlab.com",),
    "NPM_TOKEN": ("npmjs.org", "npmjs.com"),
    "PYPI_TOKEN": ("pypi.org",),
    "OPENAI_API_KEY": ("openai.com",),
    "ANTHROPIC_API_KEY": ("anthropic.com",),
    "GOOGLE_API_KEY": ("googleapis.com", "google.com"),
    "GEMINI_API_KEY": ("googleapis.com", "google.com"),
    "GOOGLE_APPLICATION_CREDENTIALS": ("googleapis.com", "google.com"),
    "AZURE_CLIENT_SECRET": ("microsoft.com", "azure.com", "windows.net", "microsoftonline.com"),
    "SLACK_TOKEN": ("slack.com",),
    "SLACK_BOT_TOKEN": ("slack.com",),
    "DISCORD_TOKEN": ("discord.com", "discordapp.com"),
    "STRIPE_SECRET_KEY": ("stripe.com",),
    "TWILIO_AUTH_TOKEN": ("twilio.com",),
    "SENDGRID_API_KEY": ("sendgrid.com", "sendgrid.net"),
    "HF_TOKEN": ("huggingface.co",),
    "HUGGINGFACE_TOKEN": ("huggingface.co",),
    "CLOUDFLARE_API_TOKEN": ("cloudflare.com",),
    "VERCEL_TOKEN": ("vercel.com", "vercel.app"),
    "HEROKU_API_KEY": ("heroku.com",),
    "DIGITALOCEAN_TOKEN": ("digitalocean.com",),
    "DOCKER_PASSWORD": ("docker.com", "docker.io"),
    "NOTION_TOKEN": ("notion.com", "notion.so"),
    "NOTION_API_KEY": ("notion.com", "notion.so"),
    "LINEAR_API_KEY": ("linear.app",),
    "JIRA_API_TOKEN": ("atlassian.com", "atlassian.net"),
    "ATLASSIAN_API_TOKEN": ("atlassian.com", "atlassian.net"),
    "DATABASE_URL": (),
    "SUPABASE_SERVICE_ROLE_KEY": ("supabase.co", "supabase.com"),
}

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$|^\[?[0-9a-f:]+\]?$", re.I)


@dataclass(frozen=True)
class _Source:
    sink: Sink
    strong: bool  # credential file (strong) vs third-party env secret (needs a foreign host)
    label: str


def _sources(sinks: list[Sink]) -> list[_Source]:
    out: list[_Source] = []
    for s in sinks:
        if s.cls == "fs_read":
            text = s.detail or s.snippet
            m = CREDENTIAL_PATH_RE.search(text or "")
            if m:
                shown = s.detail or m.group(0).strip(" \"'`$/")
                out.append(_Source(s, True, f"credential file ({shown})"))
        elif s.cls == "env" and s.detail:
            name = s.detail.upper()
            if name in SERVICE_ENV:
                out.append(_Source(s, False, f"third-party secret {s.detail}"))
    return out


def _host_owned(host: str, suffixes: tuple[str, ...]) -> bool:
    h = host.lower().rstrip(".")
    return any(h == suf or h.endswith("." + suf) for suf in suffixes)


def _foreign_hosts(sources: list[_Source], hosts: list[str]) -> list[str]:
    """Hosts that none of the env-derived services own. Unknown (non-literal) hosts are not listed."""
    allowed: set[str] = set()
    for src in sources:
        if not src.strong and src.sink.detail:
            allowed.update(SERVICE_ENV.get(src.sink.detail.upper(), ()))
    return sorted(h for h in hosts if not _host_owned(h, tuple(allowed)))


def _confidence(manifest: PackageManifest) -> Confidence:
    if any("minified" in n for n in manifest.notes):
        return Confidence.LOW
    return Confidence.HIGH if manifest.attribution == "ast" else Confidence.MEDIUM


def _lower(c: Confidence) -> Confidence:
    return {Confidence.HIGH: Confidence.MEDIUM, Confidence.MEDIUM: Confidence.LOW}.get(c, c)


def _evidence(
    path: str, sources: list[_Source], net: list[Sink]
) -> list[tuple[str, str, str | None]]:
    ev: list[tuple[str, str, str | None]] = []
    for src in sources[:3]:
        s = src.sink
        ev.append((path, f"{s.file}:{s.line} {s.snippet or s.callee}", src.label))
    seen: set[tuple[str, int]] = set()
    for s in net:
        if (s.file, s.line) in seen or len(seen) == 2:
            continue
        seen.add((s.file, s.line))
        ev.append(
            (
                path,
                f"{s.file}:{s.line} {s.snippet or s.callee}",
                f"{PHRASES['network']}" + (f" ({s.detail})" if s.detail else ""),
            )
        )
    return ev


def _judge(sources: list[_Source], net: list[Sink]) -> tuple[Severity, bool, list[str], str] | None:
    """Severity, whether confidence should drop a step, the foreign hosts, and a phrase."""
    if not sources or not net:
        return None
    hosts = sorted({s.detail for s in net if s.detail})
    strong = [s for s in sources if s.strong]
    if strong:
        raw_ip = [h for h in hosts if _IP_RE.match(h)]
        what = "reads " + ", ".join(sorted({s.label for s in strong})) + " and reaches the network"
        if hosts:
            what += " (" + ", ".join(hosts[:3]) + (", …" if len(hosts) > 3 else "") + ")"
        return Severity.HIGH, False, raw_ip or hosts, what
    foreign = _foreign_hosts(sources, hosts)
    names = ", ".join(sorted({s.sink.detail or "" for s in sources}))
    if foreign:
        return (
            Severity.MEDIUM,
            False,
            foreign,
            f"reads {names} and sends to a host that service does not own ({', '.join(foreign[:3])})",
        )
    if not hosts:
        return (
            Severity.MEDIUM,
            True,
            [],
            f"reads {names} and reaches the network through a host the analyser could not read",
        )
    return None  # every literal host belongs to the service the secret is for


@register("CFG-021", "config")
def check_credential_egress(server: ServerConfig, ctx: Context) -> list[Finding]:
    m = ctx.manifests.get(server.name)
    if m is None:
        return []
    path = f"{server.json_path}.command"
    conf = _confidence(m)
    findings: list[Finding] = []
    attributed = [tc for tc in m.tools.values() if tc.handler]
    for tc in sorted(attributed, key=lambda t: t.name):
        verdict = _judge(_sources(tc.sinks), [s for s in tc.sinks if s.cls == "network"])
        if verdict is None:
            continue
        sev, drop, _hosts, what = verdict
        findings.append(
            emit(
                ctx,
                "CFG-021",
                affected=Affected(server.source_file, path, server=server.name, tool=tc.name),
                evidence=_evidence(
                    path, _sources(tc.sinks), [s for s in tc.sinks if s.cls == "network"]
                ),
                description=f"Server '{server.name}': the handler of tool '{tc.name}' ({m.root}/{tc.handler}) "
                f"{what}. A tool has no reason to read another service's credentials, and a static "
                "reading cannot tell a backup from an exfiltration.",
                severity=sev,
                confidence=_lower(conf) if drop else conf,
                key=f"tool:{tc.name}",
            )
        )
    if findings or attributed:
        return findings
    # No handler could be attributed: judge the package as a whole, one step quieter.
    verdict = _judge(_sources(m.sinks), [s for s in m.sinks if s.cls == "network"])
    if verdict is None:
        return []
    sev, _drop, _hosts, what = verdict
    quieter = Severity.MEDIUM if sev == Severity.HIGH else Severity.LOW
    return [
        emit(
            ctx,
            "CFG-021",
            affected=Affected(server.source_file, path, server=server.name),
            evidence=_evidence(path, _sources(m.sinks), [s for s in m.sinks if s.cls == "network"]),
            description=f"Server '{server.name}' launches {m.name} ({m.root}), whose code {what}. No tool "
            "handler could be attributed, so this is a package-level observation.",
            severity=quieter,
            confidence=_lower(conf),
            key="package",
        )
    ]
