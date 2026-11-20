"""Reading real host state.

Every reader is a thin wrapper over one command and returns plain data, or
``None`` when the thing it asked about is not there. A missing tool is a normal
answer, not an exception: the auditor runs on hosts where Tailscale or the
Mac-specific register does not exist.
"""

import glob
import json
import re
import subprocess
from pathlib import Path

# ufw rule rows have a fixed Action column, but the To column before it may be
# one token ("22/tcp") or two ("172.17.0.1 53/udp"). Anchor on the action.
_ACTIONS = {"ALLOW", "DENY", "REJECT", "LIMIT"}
_PORT_RE = re.compile(r"\d+/[a-z]+")

# The volatile register and device path for Intel Mac mini power restore.
LPC_ADDRESS = "00:1f.0"
LPC_REGISTER = "0xa4.b"
POWER_UNIT = "mac-mini-power-restore.service"

# A local CLI that answers from a socket or a file needs well under a second.
# Five seconds is generous for every reader here — `ufw status verbose`,
# `tailscale status --json`, `sshd -T`, `setpci`, `systemctl` — and a command
# that has not answered by then is hung, not slow. An auditor that can be held
# for 30s per reader is an availability problem on the monitoring path: five
# readers stalled in sequence would block the audit for two and a half minutes.
TIMEOUT_SECONDS = 5


# Readers record why they could not run, so the audit can say "I could not
# tell" instead of reading an empty answer as a clean one. The map is drained
# by collector_errors().
_ERRORS: dict[str, str] = {}


def _record_error(name: str, reason: str) -> None:
    _ERRORS[name] = reason


def collector_errors() -> dict:
    """Map reader name to the reason it could not run, and clear it.

    A reader that answered is absent from the map; a reader that raised
    ``FileNotFoundError`` is ``"not installed"``, a timeout is ``"timed out"``,
    and a command that answered non-zero is ``"exit <code>"``.
    """
    errors = dict(_ERRORS)
    _ERRORS.clear()
    return errors


def _run(cmd: list, name: str | None = None) -> subprocess.CompletedProcess:
    """Run a reader's command, recording why it failed when it has a name.

    Readers that already have a finding of their own (the firewall pair reports
    ``sshd.firewall_unreadable``) pass no name, so a single failure is reported
    once rather than twice.
    """
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_SECONDS)
    except FileNotFoundError:
        if name:
            _record_error(name, "not installed")
        raise
    except subprocess.TimeoutExpired:
        if name:
            _record_error(name, "timed out")
        raise


def tailscale_status() -> dict | None:
    """Return the parsed ``tailscale status --json`` payload, or None."""
    try:
        done = _run(["tailscale", "status", "--json"], "tailscale_status")
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        _record_error("tailscale_status", f"exit {done.returncode}")
        return None
    try:
        return json.loads(done.stdout)
    except json.JSONDecodeError:
        return None


def ufw_rules() -> list | None:
    """Parse ``ufw status verbose`` into rule dicts.

    Returns ``None`` when the firewall could not be read at all — the tool is
    missing, or it failed (on Arch/Omarchy ``ufw`` is a root-only wrapper that
    exits non-zero for an unprivileged caller). An empty list means the command
    answered and there were no rules. The two must not share a representation:
    a check that cannot read its input has not passed.
    """
    try:
        done = _run(["ufw", "status", "verbose"])
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
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
    try:
        done = _run(["ufw", "status", "verbose"])
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
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
    try:
        done = _run(["sshd", "-T"], "sshd_config")
    except (OSError, subprocess.SubprocessError):
        done = None
    if done is not None and done.returncode == 0:
        return _parse_sshd_config(done.stdout) | {"source": "sshd -T"}

    text = _read_sshd_files()
    if not text.strip():
        return None
    return _parse_sshd_config(text) | {"source": "files"}


def tailscale_services() -> list:
    """List what this node publishes with ``tailscale serve`` and ``funnel``.

    ``tailscale status --json`` carries no serve or funnel state: a node can be
    ``Running`` and still be funneling a port to the internet. The serve command
    prints its own configuration, and ``AllowFunnel`` is the flag that says
    whether a port is published beyond the tailnet.

    Returns one dict per published port: ``service`` (``funnel`` or ``serve``),
    ``port`` and ``target`` (``internet`` or ``tailnet``). Empty when nothing is
    published, and empty when the tool is missing — an absent tool is a normal
    host, not an error.
    """
    try:
        done = _run(["tailscale", "serve", "status", "--json"], "tailscale_services")
    except (OSError, subprocess.SubprocessError):
        return []
    if done.returncode != 0:
        _record_error("tailscale_services", f"exit {done.returncode}")
        return []
    try:
        config = json.loads(done.stdout)
    except json.JSONDecodeError:
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
    state = {"present": False, "register": None, "unit_enabled": None, "unit_active": None}

    try:
        done = _run(["setpci", "-s", LPC_ADDRESS, LPC_REGISTER])
    except (OSError, subprocess.SubprocessError):
        return state

    if done.returncode == 0 and done.stdout.strip():
        state["present"] = True
        try:
            state["register"] = int(done.stdout.strip(), 16)
        except ValueError:
            state["register"] = None

    state["unit_enabled"] = unit_enabled(POWER_UNIT)
    state["unit_active"] = unit_active(POWER_UNIT)
    return state


def clock_state() -> dict:
    """Read whether the host's clock is being synchronised.

    ``timedatectl show -p NTPSynchronized --value`` answers ``yes`` or ``no``;
    the human-readable output is locale-dependent and is not parsed. An empty
    dict means the tool is absent, which the check reads as unknown rather than
    as broken.
    """
    state: dict = {}
    try:
        done = _run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"])
    except (OSError, subprocess.SubprocessError):
        return state
    if done.returncode == 0:
        answer = done.stdout.strip().lower()
        if answer in ("yes", "no"):
            state["synchronised"] = answer == "yes"

    state["service_active"] = unit_active("systemd-timesyncd")
    return state


def pending_update_count() -> int | None:
    """Count pending package updates, or None when there is no supported manager.

    ``checkupdates`` (pacman/Arch) is present on the target host and prints one
    line per update. Its output is suppressed when the local metadata is stale,
    so the count can be 0 for "no updates" and 0 for "never refreshed" — the
    auditor does not try to tell those apart, and a refresh is cheap.

    ``None`` means the answer is unknown: no manager, or the command failed.
    That is not a finding.

    ``checkupdates`` exits 2 when there ARE updates, 0 when there are none and 1
    on error, so only 1 (or anything unexpected) is a failure.
    """
    try:
        done = _run(["checkupdates"], "pending_update_count")
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode not in (0, 2):
        return None
    return len([line for line in done.stdout.splitlines() if line.strip()])


def unit_enabled(name: str) -> bool | None:
    """Return whether a systemd unit is enabled, or None if systemctl fails."""
    try:
        done = _run(["systemctl", "is-enabled", name])
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        return False
    return done.stdout.strip() == "enabled"


def unit_active(name: str) -> bool | None:
    """Return whether a systemd unit's last run succeeded, or None if systemctl fails.

    ``is-active`` answers a different question from ``is-enabled``: a unit can be
    enabled and still have failed on the last boot. For a oneshot that writes a
    volatile register, that difference is the whole point.
    """
    try:
        done = _run(["systemctl", "is-active", name])
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        return False
    return done.stdout.strip() == "active"
