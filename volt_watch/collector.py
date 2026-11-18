"""Reading real host state.

Every reader is a thin wrapper over one command and returns plain data, or
``None`` when the thing it asked about is not there. A missing tool is a normal
answer, not an exception: the auditor runs on hosts where Tailscale or the
Mac-specific register does not exist.
"""

import json
import re
import subprocess

# ufw rule rows have a fixed Action column, but the To column before it may be
# one token ("22/tcp") or two ("172.17.0.1 53/udp"). Anchor on the action.
_ACTIONS = {"ALLOW", "DENY", "REJECT", "LIMIT"}
_PORT_RE = re.compile(r"\d+/[a-z]+")

# The volatile register and device path for Intel Mac mini power restore.
LPC_ADDRESS = "00:1f.0"
LPC_REGISTER = "0xa4.b"
POWER_UNIT = "mac-mini-power-restore.service"


def _run(cmd: list) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=30)


def tailscale_status() -> dict | None:
    """Return the parsed ``tailscale status --json`` payload, or None."""
    try:
        done = _run(["tailscale", "status", "--json"])
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        return None
    try:
        return json.loads(done.stdout)
    except json.JSONDecodeError:
        return None


def ufw_rules() -> list:
    """Parse ``ufw status verbose`` into rule dicts."""
    try:
        done = _run(["ufw", "status", "verbose"])
    except (OSError, subprocess.SubprocessError):
        return []
    if done.returncode != 0:
        return []

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


def ufw_default_incoming() -> str:
    """Return the firewall's default incoming policy: ``allow`` or ``deny``."""
    try:
        done = _run(["ufw", "status", "verbose"])
    except (OSError, subprocess.SubprocessError):
        return "deny"
    if done.returncode != 0:
        return "deny"

    for line in done.stdout.splitlines():
        if line.startswith("Default:"):
            match = line.split("incoming)", 1)
            policy = match[0].rsplit(":", 1)[-1].strip()
            return policy if policy in ("allow", "deny") else "deny"
    return "deny"


def power_restore_state() -> dict:
    """Read the power-restore register and the boot unit that rewrites it."""
    state = {"present": False, "register": None, "unit_enabled": None}

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
    return state


def unit_enabled(name: str) -> bool | None:
    """Return whether a systemd unit is enabled, or None if systemctl fails."""
    try:
        done = _run(["systemctl", "is-enabled", name])
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        return False
    return done.stdout.strip() == "enabled"
