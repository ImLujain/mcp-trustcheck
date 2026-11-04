"""CFG-007: privileged container launch (threat-model.md T5)."""

from __future__ import annotations

import re

from mcp_trustcheck.checks import Context, emit, register
from mcp_trustcheck.checks._util import basename
from mcp_trustcheck.model import Affected, ConfigValue, Finding, ServerConfig

RUNTIMES = {"docker", "podman", "nerdctl"}
DANGEROUS_FLAGS: dict[str, str] = {
    "--privileged": "all capabilities, all devices, no seccomp/AppArmor",
    "--pid=host": "shares the host PID namespace",
    "--ipc=host": "shares the host IPC namespace",
    "--userns=host": "disables user-namespace isolation",
    "--network=host": "shares the host network namespace",
    "--net=host": "shares the host network namespace",
}
VALUE_FLAGS = {
    "--pid",
    "--ipc",
    "--userns",
    "--network",
    "--net",
    "--cap-add",
    "--security-opt",
    "--user",
    "-u",
    "-v",
    "--volume",
    "--mount",
    "--device",
}
_CAP_RE = re.compile(
    r"(?i)^(?:ALL|SYS_ADMIN|SYS_PTRACE|SYS_MODULE|SYS_RAWIO|NET_ADMIN|DAC_READ_SEARCH|SYS_BOOT)$"
)
_UNCONFINED_RE = re.compile(
    r"(?i)(?:seccomp|apparmor)[=:]unconfined|label[=:]disable|no-new-privileges[=:]false"
)
_SOCKET_RE = re.compile(r"(?:docker|podman|containerd)\.sock|/run/containerd")


def _flag_pairs(server: ServerConfig) -> list[tuple[ConfigValue, str, str]]:
    """Yield (arg, flag, value) with `--flag value` and `--flag=value` normalised."""
    out: list[tuple[ConfigValue, str, str]] = []
    args = server.args
    i = 0
    while i < len(args):
        a = args[i]
        v = a.value
        if "=" in v and v.startswith("--"):
            flag, val = v.split("=", 1)
            out.append((a, flag, val))
        elif v in VALUE_FLAGS and i + 1 < len(args):
            out.append((args[i + 1], v, args[i + 1].value))
            i += 2
            continue
        else:
            out.append((a, v, ""))
        i += 1
    return out


@register("CFG-007", "config")
def check_privileged_container(server: ServerConfig, ctx: Context) -> list[Finding]:
    if not server.command or basename(server.command).removesuffix(".exe") not in RUNTIMES:
        return []
    if not server.arg_values or server.arg_values[0] not in ("run", "create", "container"):
        return []
    hits: list[tuple[ConfigValue, str]] = []
    for arg, flag, val in _flag_pairs(server):
        norm = f"{flag}={val}" if val else flag
        if norm in DANGEROUS_FLAGS:
            hits.append((arg, f"{norm}: {DANGEROUS_FLAGS[norm]}"))
        elif flag == "--cap-add" and _CAP_RE.match(val.strip()):
            hits.append(
                (arg, f"--cap-add {val}: grants a capability that breaks container isolation")
            )
        elif flag == "--security-opt" and _UNCONFINED_RE.search(val):
            hits.append((arg, f"--security-opt {val}: disables a sandbox layer"))
        elif flag in ("--user", "-u") and val.strip().split(":")[0] in ("0", "root"):
            hits.append((arg, f"{flag} {val}: runs as root inside the container"))
        elif flag in ("-v", "--volume", "--mount") and _SOCKET_RE.search(val):
            hits.append(
                (
                    arg,
                    f"{flag} {val}: container runtime socket mounted — equivalent to root on the host",
                )
            )
        elif flag == "--device" and val.strip() in ("/dev", "/dev/mem", "/dev/kmem"):
            hits.append((arg, f"--device {val}: raw host device access"))
    if not hits:
        return []
    return [
        emit(
            ctx,
            "CFG-007",
            affected=Affected(server.source_file, server.json_path, server=server.name),
            evidence=[(a.json_path, a.value, note) for a, note in hits],
            description=f"Container for server '{server.name}' is started with {len(hits)} option(s) that "
            "remove the isolation a container is supposed to provide.",
        )
    ]
