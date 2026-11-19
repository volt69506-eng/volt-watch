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
        done = _run(["sshd", "-T"])
    except (OSError, subprocess.SubprocessError):
        done = None
    if done is not None and done.returncode == 0:
        return _parse_sshd_config(done.stdout) | {"source": "sshd -T"}

    text = _read_sshd_files()
    if not text.strip():
        return None
    return _parse_sshd_config(text) | {"source": "files"}


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
