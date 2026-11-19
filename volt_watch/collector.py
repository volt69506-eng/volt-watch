"""Reading real host state.

Readers return plain data or their existing empty values. Command failures are
also recorded separately so the audit can report what it could not inspect.
"""

import glob
import json
import re
import subprocess
from pathlib import Path
from threading import local

# ufw rule rows have a fixed Action column, but the To column before it may be
# one token ("22/tcp") or two ("172.17.0.1 53/udp"). Anchor on the action.
_ACTIONS = {"ALLOW", "DENY", "REJECT", "LIMIT"}
_PORT_RE = re.compile(r"\d+/[a-z]+")

# The volatile register and device path for Intel Mac mini power restore.
LPC_ADDRESS = "00:1f.0"
LPC_REGISTER = "0xa4.b"
POWER_UNIT = "mac-mini-power-restore.service"


class _ReaderState(local):
    def __init__(self):
        self.errors: dict[str, str] = {}


_reader_state = _ReaderState()


def collector_errors() -> dict[str, str]:
    """Return a snapshot of failed readers for the current thread."""
    return _reader_state.errors.copy()


def reset_collector_errors() -> None:
    """Begin a new collection without carrying over earlier failures."""
    _reader_state.errors.clear()


def _run(reader: str, cmd: list[str]) -> subprocess.CompletedProcess[str] | None:
    errors = _reader_state.errors
    errors.pop(reader, None)
    try:
        done = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        errors[reader] = "timed out"
    except OSError:
        errors[reader] = "not installed"
    except subprocess.SubprocessError:
        errors[reader] = "command failed"
    else:
        if done.returncode:
            errors[reader] = f"exit {done.returncode}"
        return done
    return None


def tailscale_status() -> dict | None:
    """Return the parsed ``tailscale status --json`` payload, or None."""
    done = _run("tailscale_status", ["tailscale", "status", "--json"])
    if done is None or done.returncode != 0:
        return None
    try:
        return json.loads(done.stdout)
    except json.JSONDecodeError:
        _reader_state.errors["tailscale_status"] = "invalid JSON"
        return None


def ufw_rules() -> list | None:
    """Parse ``ufw status verbose`` into rule dicts.

    Returns ``None`` when the firewall could not be read at all — the tool is
    missing, or it failed (on Arch/Omarchy ``ufw`` is a root-only wrapper that
    exits non-zero for an unprivileged caller). An empty list means the command
    answered and there were no rules. The two must not share a representation:
    a check that cannot read its input has not passed.
    """
    done = _run("ufw_rules", ["ufw", "status", "verbose"])
    if done is None or done.returncode != 0:
        return None

    rules = []
    in_table = False
    for line in done.stdout.splitlines():
        if line.startswith("To "):
            in_table = True
            continue
        if not in_table:
            continue
        if not line.strip():
            break
        # The dashed separator row under the header.
        if line.lstrip().startswith("--"):
            continue

        # Split on the action token: everything before it is the To column
        # (a port, optionally preceded by an address), everything after is
        # the direction and From column. Trailing "# ..." is a user comment.
        columns = line.split("#", 1)[0].split()
        action_index = next(
            (i for i, token in enumerate(columns) if token in _ACTIONS),
            None,
        )
        if action_index is None or action_index == 0:
            continue

        action = columns[action_index]
        target = columns[:action_index]
        rest = columns[action_index + 1:]

        # ufw writes the direction as its own column ("ALLOW IN"); it is not
        # part of the source.
        if rest and rest[0] in ("IN", "OUT"):
            rest = rest[1:]
        source = " ".join(rest).strip()

        # The interface qualifier ("on <iface>") may follow the port.
        interface = ""
        if len(target) >= 2 and target[-2] == "on":
            interface = target[-1]
            target = target[:-2]

        # The port is the "<num>/<proto>" token; any leading token is an
        # address ufw printed alongside it in the To column.
        port = ""
        address = ""
        for token in target:
            if _PORT_RE.fullmatch(token):
                port = token
            else:
                address = token

        rules.append(
            {
                "port": port,
                "action": action,
                "interface": interface,
                "source": source,
                "address": address,
            }
        )
    return rules


def ufw_default_incoming() -> str | None:
    """Return the firewall's default incoming policy: ``allow`` or ``deny``.

    Returns ``None`` when it could not be read. Falling back to ``"deny"`` on a
    failed read would report the safe-looking answer for a firewall that was
    never inspected.
    """
    done = _run("ufw_default_incoming", ["ufw", "status", "verbose"])
    if done is None or done.returncode != 0:
        return None

    for line in done.stdout.splitlines():
        if line.startswith("Default:"):
            # The line lists both directions: "Default: deny (incoming), allow
            # (outgoing)". Read the incoming clause specifically, rather than
            # splitting on the first ")" — which lands inside the clause when
            # both are present.
            match = re.search(r"(\w+)\s*\(incoming\)", line)
            return match.group(1) if match and match.group(1) in ("allow", "deny") else None
    return None


def _read_sshd_files() -> str:
    """Read the effective sshd configuration by hand: the main file, then drop-ins.

    ``sshd`` applies the last value it sees, so the drop-ins come after the main
    file and later files in the glob win. Used when ``sshd -T`` cannot run.
    """
    parts = []
    for path in ["/etc/ssh/sshd_config", *sorted(glob.glob("/etc/ssh/sshd_config.d/*.conf"))]:
        try:
            parts.append(Path(path).read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
    return "\n".join(parts)


def _parse_sshd_config(text: str) -> dict:
    """Pull the two authentication settings out of sshd configuration text.

    ``permitrootlogin`` accepts several values; only ``yes`` means root may sign
    in with a password, so ``prohibit-password`` and ``forced-commands-only``
    are not root login.
    """
    wanted = {"passwordauthentication": "password_authentication", "permitrootlogin": "permit_root_login"}
    values: dict[str, str] = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        key = parts[0].lower()
        if key in wanted and key not in values:
            values[key] = parts[1].strip().lower()

    def _bool(value: str | None) -> bool | None:
        if value is None:
            return None
        if value in ("yes", "true", "1"):
            return True
        if value in ("no", "false", "0", "prohibit-password", "without-password", "forced-commands-only"):
            return False
        return None

    return {
        "password_authentication": _bool(values.get("passwordauthentication")),
        "permit_root_login": _bool(values.get("permitrootlogin")),
    }


def sshd_config() -> dict | None:
    """Read sshd's effective configuration, or ``None`` if neither route works.

    ``sshd -T`` prints the effective configuration, which is the only correct
    answer — it applies ``Match`` blocks and the drop-in precedence. It needs
    root (it loads the host keys), so an unprivileged run falls back to reading
    the files, and the dict says which route produced it.
    """
    done = _run("sshd_config", ["sshd", "-T"])
    if done is not None and done.returncode == 0:
        return _parse_sshd_config(done.stdout) | {"source": "sshd -T"}

    text = _read_sshd_files()
    if not text.strip():
        return None
    _reader_state.errors.pop("sshd_config", None)
    return _parse_sshd_config(text) | {"source": "files"}


def tailscale_services() -> list:
    """List what this node publishes with ``tailscale serve`` and ``funnel``.

    ``tailscale status --json`` carries no serve or funnel state: a node can be
    ``Running`` and still be funneling a port to the internet. The serve command
    prints its own configuration, and ``AllowFunnel`` is the flag that says
    whether a port is published beyond the tailnet.

    Returns one dict per published port: ``service`` (``funnel`` or ``serve``),
    ``port`` and ``target`` (``internet`` or ``tailnet``). Empty when nothing is
    published. Command failures also return an empty list and appear in
    ``collector_errors()``.
    """
    done = _run("tailscale_services", ["tailscale", "serve", "status", "--json"])
    if done is None or done.returncode != 0:
        return []
    try:
        config = json.loads(done.stdout)
    except json.JSONDecodeError:
        _reader_state.errors["tailscale_services"] = "invalid JSON"
        return []
    if not isinstance(config, dict):
        return []

    funnel_ports = set()
    for key, enabled in (config.get("AllowFunnel") or {}).items():
        if enabled:
            funnel_ports.add(_port_of(str(key)))

    services = []
    for port, handler in (config.get("TCP") or {}).items():
        if not isinstance(handler, dict):
            continue
        services.append(_service(str(port), funnel_ports))

    for host_port in (config.get("Web") or {}):
        services.append(_service(str(host_port), funnel_ports))

    return services


def _port_of(host_port: str) -> str:
    """Take the port out of a ``host:port`` key, tolerating a bare port."""
    return host_port.rsplit(":", 1)[-1]


def _service(key: str, funnel_ports: set) -> dict:
    """Build one published-service record, deciding funnel from its port."""
    published = _port_of(key)
    is_funnel = published in funnel_ports
    return {
        "service": "funnel" if is_funnel else "serve",
        "port": published,
        "target": "internet" if is_funnel else "tailnet",
    }


def power_restore_state() -> dict:
    """Read the power-restore register and the boot unit that rewrites it."""
    state = {"present": False, "register": None, "unit_enabled": None}

    done = _run("power_restore_state", ["setpci", "-s", LPC_ADDRESS, LPC_REGISTER])
    if done is None:
        return state

    if done.returncode == 0 and done.stdout.strip():
        state["present"] = True
        try:
            state["register"] = int(done.stdout.strip(), 16)
        except ValueError:
            state["register"] = None

    state["unit_enabled"] = unit_enabled(POWER_UNIT)
    return state


def unit_enabled(name: str) -> bool | None:
    """Return whether a systemd unit is enabled, or None if systemctl fails."""
    done = _run("unit_enabled", ["systemctl", "is-enabled", name])
    if done is None:
        return None
    if done.returncode != 0:
        if done.returncode == 1 and done.stdout.strip() in {"disabled", "masked", "masked-runtime"}:
            _reader_state.errors.pop("unit_enabled", None)
        return False
    return done.stdout.strip() == "enabled"
