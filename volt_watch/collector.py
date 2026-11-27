"""Reading real host state.

Every reader is a thin wrapper over one command and returns plain data, or
``None`` when the thing it asked about is not there. A missing tool is a normal
answer, not an exception: the auditor runs on hosts where Tailscale or the
Mac-specific register does not exist.
"""

import glob
import json
import os
import re
import socket
import stat
import subprocess
from pathlib import Path

# Reader seam: tests point this at a fake /proc tree. Production never changes it.
PROC_ROOT = Path("/proc")

# ufw rule rows have a fixed Action column, but the To column before it may be
# one token ("22/tcp") or two ("172.17.0.1 53/udp"). Anchor on the action.
_ACTIONS = {"ALLOW", "DENY", "REJECT", "LIMIT"}
_PORT_RE = re.compile(r"\d+/[a-z]+")

# The volatile register and device path for Intel Mac mini power restore.
LPC_ADDRESS = "00:1f.0"
LPC_REGISTER = "0xa4.b"
POWER_UNIT = "mac-mini-power-restore.service"

# Small, defensible allowlist of sensitive local paths. Missing paths are not
# findings; unreadable paths are reported as unknown state by the check.
SENSITIVE_PATH_SPECS = [
    {"path": "/crypto_keyfile.bin", "kind": "luks_keyfile"},
    {"path": "/var/lib/tailscale/tailscaled.state", "kind": "tailscale_state"},
    {"path": "/run/docker.sock", "kind": "docker_sock"},
    {"path": "/etc/ssh/ssh_host_*_key", "kind": "ssh_host_private_key"},
]

SUDOERS_PATH = "/etc/sudoers"
SUDOERS_D_GLOB = "/etc/sudoers.d/*"

REBOOT_REQUIRED_PATHS = [
    "/run/reboot-required",
    "/var/run/reboot-required",
]

SENSITIVE_RUNTIME_DIRS = [
    "/var/lib/tailscale",
]

# A local CLI that answers from a socket or a file needs well under a second.
# Five seconds is generous for every reader here — `ufw status verbose`,
# `tailscale status --json`, `sshd -T`, `setpci`, `systemctl` — and a command
# that has not answered by then is hung, not slow. An auditor that can be held
# for 30s per reader is an availability problem on the monitoring path: five
# readers stalled in sequence would block the audit for two and a half minutes.
TIMEOUT_SECONDS = 5

# `checkupdates` is the one reader that talks to the network: it runs
# `pacman -Sy` against the mirrors before it can say whether anything is
# pending. Five seconds is not enough for that on a slow mirror, and a slow
# mirror is not a hung reader — it used to surface as `auditor.degraded` on a
# host that was fine. It still has a budget: thirty seconds, far below the
# monitoring interval, and the same "could not run" reporting when it expires.
CHECKUPDATES_TIMEOUT_SECONDS = 30


# Readers record why they could not run, so the audit can say "I could not
# tell" instead of reading an empty answer as a clean one. The map is drained
# by collector_errors().
_ERRORS: dict[str, dict[str, str]] = {}


def _record_error(name: str, reason: str, kind: str) -> None:
    _ERRORS[name] = {"reader": name, "reason": reason, "kind": kind}


def collector_errors() -> dict[str, dict[str, str]]:
    """Map reader names to failure records, and clear them.

    Each record has ``reader``, a safe human-readable ``reason``, and a stable
    ``kind``: timeout, missing_tool, permission, command_failed or unknown.
    Reasons never include command output or exception text. A reader that
    answered is absent from the map.
    """
    errors = dict(_ERRORS)
    _ERRORS.clear()
    return errors


def _run(cmd: list, name: str | None = None, timeout: int = TIMEOUT_SECONDS) -> subprocess.CompletedProcess:
    """Run a reader's command, recording why it failed when it has a name.

    Readers that already have a finding of their own (the firewall pair reports
    ``sshd.firewall_unreadable``) pass no name, so a single failure is reported
    once rather than twice.

    ``timeout`` defaults to the budget every local reader gets; a reader that
    reaches the network passes its own.
    """
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        if name:
            _record_error(name, "not installed", "missing_tool")
        raise
    except subprocess.TimeoutExpired:
        if name:
            _record_error(name, f"timed out after {timeout}s", "timeout")
        raise
    except PermissionError:
        if name:
            _record_error(name, "permission denied", "permission")
        raise
    except (OSError, subprocess.SubprocessError):
        if name:
            _record_error(name, "could not run", "unknown")
        raise


def tailscale_status() -> dict | None:
    """Return the parsed ``tailscale status --json`` payload, or None."""
    try:
        done = _run(["tailscale", "status", "--json"], "tailscale_status")
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        _record_error("tailscale_status", f"exit {done.returncode}", "command_failed")
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
            return match.group(1) if match else None
    return None


def ufw_active() -> bool | None:
    """Report whether UFW is active.

    ``None`` when state cannot be read. The positive disabled case is reported
    by ``firewall.disabled``; unreadable remains unknown.
    """
    try:
        done = _run(["ufw", "status", "verbose"])
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        return None
    for line in done.stdout.splitlines():
        stripped = line.strip().lower()
        if stripped.startswith("status:"):
            if "inactive" in stripped:
                return False
            if "active" in stripped:
                return True
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
    if done is not None:
        _record_error("sshd_config", f"exit {done.returncode}", "command_failed")

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
        _record_error("tailscale_services", f"exit {done.returncode}", "command_failed")
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

    pacman-contrib's ``checkupdates`` exits 2 when there are no updates and 0
    when there are, which is the reverse of what this docstring used to claim;
    both are accepted so a tool that changed its contract still answers. Exit 1
    is an error. It runs ``pacman -Sy`` first, so it gets
    ``CHECKUPDATES_TIMEOUT_SECONDS`` rather than the local budget.
    """
    try:
        done = _run(
            ["checkupdates"],
            "pending_update_count",
            timeout=CHECKUPDATES_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode not in (0, 2):
        _record_error("pending_update_count", f"exit {done.returncode}", "command_failed")
        return None
    return len([line for line in done.stdout.splitlines() if line.strip()])


def disk_usage(path: str = "/") -> dict | None:
    """Return byte and inode use for ``path``, or None if it cannot be read.

    ``shutil.disk_usage`` gives bytes; the inode side needs ``statvfs`` and is
    here because the two can disagree: a host with terabytes free can still be
    dead when a directory of small files exhausted its inodes, and ``df -h``
    would not show it.

    Only ``OSError`` yields ``None``; a zero value is a real answer and is
    reported, not treated as unknown.
    """
    try:
        st = os.statvfs(path)
    except OSError:
        return None
    total = st.f_blocks * st.f_frsize
    free = st.f_bavail * st.f_frsize
    if st.f_blocks == 0 or st.f_files == 0:
        return None
    return {
        "total": total,
        "used": total - st.f_bfree * st.f_frsize,
        "free": free,
        "percent_used": round((st.f_blocks - st.f_bfree) / st.f_blocks * 100, 1),
        "inode_percent_used": round(
            (st.f_files - st.f_ffree) / st.f_files * 100, 1
        ),
    }


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


def failed_units() -> list | None:
    """Return the systemd units in a failed state, or None if systemctl fails.

    ``systemctl --failed --no-legend --plain`` prints one row per unit:

        sshd.service loaded failed failed OpenBSD Secure Shell server

    The four leading columns are the unit, its load, active and sub state;
    the rest is the description, which is not read here. ``--plain`` keeps
    systemd from truncating a long unit name with an ellipsis, so the name in
    the report is the real one.

    ``None`` means the question could not be asked, which is not the same as
    "nothing failed".
    """
    try:
        done = _run(["systemctl", "--failed", "--no-legend", "--plain"])
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        return None
    units = []
    for line in done.stdout.splitlines():
        fields = line.split(None, 4)
        if len(fields) < 4:
            continue
        units.append(
            {
                "name": fields[0],
                "load": fields[1],
                "active": fields[2],
                "sub": fields[3],
            }
        )
    return units


# Packages that start with "linux" but are not kernels: firmware blobs, headers
# to build modules against, API headers, docs. None of them carries the running
# kernel's version, so a list of installed kernels built from `pacman -Q` must
# leave them out. Matched as a substring, not a suffix: `linux-firmware-amd`
# and `linux-firmware-whence` are firmware too, and a suffix list would let a
# dozen of them in and make every comparison look like a newer kernel.
NON_KERNEL_MARKERS = (
    "firmware",
    "headers",
    "api-headers",
    "docs",
    "tools",
    "source",
)


def normalize_release(release: str) -> str:
    """``7.2.15-1-omarchy`` -> ``7.2.15-1``, the distro suffix dropped.

    ``uname -r`` appends the kernel's local version, which is how the distro's
    rebuild is named; the package version is ``pkgver-pkgrel``. Keeping the
    suffix would make every comparison report a pending reboot forever.
    """
    parts = release.strip().split("-")
    if len(parts) >= 2 and re.match(r"^\d", parts[0]):
        return f"{parts[0]}-{parts[1]}"
    return release.strip()


def kernel_versions() -> dict | None:
    """Return the running and installed kernel releases, or None.

    ``running`` is ``uname -r`` verbatim (suffix included) and ``installed`` is
    the version of every installed kernel package, newest last. ``None`` means
    the question could not be asked at all: no ``uname`` or no ``pacman``.
    """
    try:
        uname = _run(["uname", "-r"])
        # `pacman -Q`, not `-Qq`: the version is the whole point, and `-Qq`
        # prints names only.
        packages = _run(["pacman", "-Q"])
    except (OSError, subprocess.SubprocessError):
        return None
    if uname.returncode != 0:
        return None
    installed = []
    if packages.returncode == 0:
        for line in packages.stdout.splitlines():
            fields = line.split()
            if len(fields) != 2:
                continue
            name, version = fields
            if not name.startswith("linux"):
                continue
            if any(marker in name for marker in NON_KERNEL_MARKERS):
                continue
            installed.append(version)
    return {
        "running": uname.stdout.strip(),
        "installed": sorted(installed),
    }


def orphaned_packages() -> list | None:
    """Return installed packages nothing requires any more, or None.

    ``pacman -Qdt`` prints one entry per orphan: the package name and version on
    an unindented line, the explanation indented below it. Only the unindented
    lines are read, so the prose never becomes a field.

    ``None`` means pacman is absent or failed, which is not the same as "no
    orphans": a non-Arch host has no pacman and is not a host with a clean
    dependency tree.

    Like ``checkupdates``, pacman exits 1 when the query matched nothing, so 0
    (orphans listed) and 1 (none) are both answers and anything else is a
    failure. Reading only the zero case would report every clean host as
    unknown, and the degraded-reader finding would fire on every healthy run.
    """
    try:
        done = _run(["pacman", "-Qdt"])
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode not in (0, 1):
        return None
    orphans = []
    for line in done.stdout.splitlines():
        if not line.strip() or line[0].isspace():
            continue
        fields = line.split()
        if len(fields) < 2:
            continue
        orphans.append({"name": fields[0], "version": fields[1]})
    return orphans


def empty_password_accounts(path: str = "/etc/shadow") -> list | None:
    """Return accounts whose password field is empty, or None if unreadable.

    ``/etc/shadow``'s second colon-separated field is the password hash. An
    empty field means the account can authenticate with no password; ``!``,
    ``*`` and a real hash are not findings. Only the account name is returned —
    never the field itself.

    A missing file yields ``[]``: a host with no account database has no
    passwordless accounts, and must not look like one it could not read. A
    file that exists but cannot be read yields ``None``, which the check reports
    as an unknown state rather than as a clean database.
    """
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return []
    except OSError:
        return None

    accounts = []
    for line in text.splitlines():
        fields = line.split(":")
        if len(fields) < 2:
            continue
        name, password = fields[0].strip(), fields[1]
        if name and password == "":
            accounts.append({"name": name})
    return accounts


# Bounds for the config-drift walk. `/etc` is shallow in practice; the depth
# keeps a stray mount point or symlinked tree from turning the audit into a
# filesystem crawl, and the entry cap bounds what a mass replacement can put
# into one report.
MAX_DRIFT_DEPTH = 4
MAX_DRIFT_ENTRIES = 200


def config_drift(root: str = "/etc") -> dict | None:
    """Return replaced config files under ``root``, or None if unreadable.

    Pacman leaves a ``.pacnew`` when it installed a new config over yours and
    a ``.pacsave`` when the package stopped installing a config it used to own.
    Both mean an administrator has a merge to review; neither changes the host
    by itself.

    The answer is ``{"pacnew": [...], "pacsave": [...], "truncated": bool}``
    with paths relative to ``root``. A readable tree with nothing to report
    gives two empty lists; a scan that could not complete — the root or any
    subdirectory unreadable — gives ``None``, so a partial answer is never
    mistaken for a clean one.
    """
    if not os.path.isdir(root):
        return None

    found = {"pacnew": [], "pacsave": []}
    truncated = False

    def walk(directory, depth):
        nonlocal truncated
        if truncated or depth > MAX_DRIFT_DEPTH:
            return
        try:
            entries = list(os.scandir(directory))
        except OSError:
            raise

        for entry in entries:
            if len(found["pacnew"]) + len(found["pacsave"]) >= MAX_DRIFT_ENTRIES:
                truncated = True
                return
            if entry.is_symlink():
                continue
            try:
                if entry.is_dir(follow_symlinks=False):
                    walk(entry.path, depth + 1)
                elif entry.is_file(follow_symlinks=False):
                    relative = os.path.relpath(entry.path, root)
                    if entry.name.endswith(".pacnew"):
                        found["pacnew"].append(relative)
                    elif entry.name.endswith(".pacsave"):
                        found["pacsave"].append(relative)
            except OSError:
                raise

    try:
        walk(root, 0)
    except OSError:
        return None

    return {
        "pacnew": sorted(found["pacnew"]),
        "pacsave": sorted(found["pacsave"]),
        "truncated": truncated,
    }


# Bound the /etc mode walk: a stray mount or symlinked tree must not turn the
# audit into a filesystem crawl. S_IWOTH is tested directly on lstat modes.
MAX_WORLD_WRITABLE_DEPTH = 4


def world_writable_etc(root: str = "/etc", max_depth: int = MAX_WORLD_WRITABLE_DEPTH) -> list | None:
    """Return world-writable paths under ``root``, or None if it cannot be read.

    Files and directories are both reported, with paths relative to ``root``
    and each mode as an ``0o...`` string. Symlinks are never followed or
    reported as themselves. A readable tree with nothing to report yields [].
    """

    if not os.path.isdir(root):
        return None

    found = []

    def walk(directory, depth):
        if depth > max_depth:
            return
        for entry in os.scandir(directory):
            if entry.is_symlink():
                continue
            mode = entry.stat(follow_symlinks=False).st_mode
            if mode & stat.S_IWOTH:
                found.append({
                    "path": os.path.relpath(entry.path, root),
                    "mode": oct(stat.S_IMODE(mode)),
                })
            if entry.is_dir(follow_symlinks=False):
                walk(entry.path, depth + 1)

    try:
        walk(root, 0)
    except OSError:
        return None
    found.sort(key=lambda item: item["path"])
    return found


def _sensitive_expected(kind: str) -> str:
    return {
        "luks_keyfile": "0400 root-owned",
        "tailscale_state": "not world-readable",
        "docker_sock": "root:docker 0660 or stricter",
        "ssh_host_private_key": "0600 root-owned",
    }.get(kind, "restricted")


def _expand_sensitive_specs(specs: list[dict]) -> list[dict]:
    expanded = []
    for spec in specs:
        pattern = spec["path"]
        matches = glob.glob(pattern)
        if matches:
            for match in sorted(matches):
                expanded.append({"path": match, "kind": spec["kind"]})
        else:
            expanded.append({"path": pattern, "kind": spec["kind"]})
    # dedupe preserving order
    seen = set()
    out = []
    for spec in expanded:
        if spec["path"] in seen:
            continue
        seen.add(spec["path"])
        out.append(spec)
    return out


def sensitive_path_records() -> list[dict]:
    """Return structured permission records for sensitive local paths.

    Missing paths are omitted. Unreadable existing paths are returned with
    ``readable=False`` so the check can report unknown state instead of silence.
    File contents are never read.
    """
    records = []
    for spec in _expand_sensitive_specs(SENSITIVE_PATH_SPECS):
        path = spec["path"]
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            continue
        except OSError:
            records.append({
                "path": path,
                "exists": True,
                "mode": None,
                "uid": None,
                "gid": None,
                "owner": None,
                "group": None,
                "readable": False,
                "expected": _sensitive_expected(spec["kind"]),
                "kind": spec["kind"],
            })
            continue

        mode = stat.S_IMODE(st.st_mode)
        owner = None
        group = None
        try:
            import pwd, grp
            owner = pwd.getpwuid(st.st_uid).pw_name
        except Exception:
            owner = str(st.st_uid)
        try:
            import grp
            group = grp.getgrgid(st.st_gid).gr_name
        except Exception:
            group = str(st.st_gid)

        records.append({
            "path": path,
            "exists": True,
            "mode": oct(mode),
            "uid": st.st_uid,
            "gid": st.st_gid,
            "owner": owner,
            "group": group,
            "readable": True,
            "expected": _sensitive_expected(spec["kind"]),
            "kind": spec["kind"],
        })
    return records


_NOTAFTER_RE = re.compile(r"\bNOTAFTER=(\d{14}Z)\b")
_NOPASSWD_RE = re.compile(r"\bNOPASSWD\s*:")


def _sudoers_includes(text: str) -> list[str]:
    includes = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            # #includedir/#include directives start with # but are directives
            if stripped.lower().startswith("#includedir"):
                pat = stripped.split(None, 1)[1].strip() if len(stripped.split(None, 1)) > 1 else ""
                if pat:
                    for match in sorted(glob.glob(pat + "/*")):
                        if os.path.basename(match).startswith(".") or match.endswith("~"):
                            continue
                        includes.append(match)
            elif stripped.lower().startswith("#include"):
                pat = stripped.split(None, 1)[1].strip() if len(stripped.split(None, 1)) > 1 else ""
                if pat:
                    for match in sorted(glob.glob(pat)):
                        includes.append(match)
            continue
    return includes


def _parse_notafter(value: str) -> str | None:
    # value like 20261123234621Z
    try:
        from datetime import datetime, timezone
        dt = datetime.strptime(value, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except Exception:
        return None


def _is_notafter_expired(value: str | None, now=None) -> bool | None:
    if not value:
        return None
    try:
        from datetime import datetime, timezone
        dt = datetime.strptime(value, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
        if now is None:
            now = datetime.now(timezone.utc)
        return dt <= now
    except Exception:
        return None


def _parse_sudoers_rules(text: str, source: str, now=None) -> list[dict]:
    rules = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "NOPASSWD" not in line.upper():
            continue
        # skip Defaults lines
        if line.lower().startswith("defaults"):
            continue
        # very small parser: split at first '=' before command spec? sudoers rules usually: user host=(runas) tags: commands
        # find commands after last ':'
        if ":" not in line:
            continue
        left, commands = line.rsplit(":", 1)
        commands = commands.strip()
        if not commands:
            continue
        upper_left = left.upper()
        if "NOPASSWD" not in upper_left and "!AUTHENTICATE" not in upper_left:
            continue
        notafter_m = _NOTAFTER_RE.search(line)
        notafter = notafter_m.group(1) if notafter_m else None
        expired = _is_notafter_expired(notafter, now=now)
        # user is first token
        user = line.split()[0]
        rules.append({
            "file": source,
            "user": user,
            "commands": commands,
            "notafter": notafter,
            "notafter_expired": expired,
            "nopasswd": True,
        })
    return rules


def passwordless_sudo_rules(now=None) -> list[dict] | None:
    """Parse sudoers for NOPASSWD rules.

    Intentionally small line-oriented parser; not a full sudoers grammar.
    Returns None when sudoers cannot be read (unknown), [] when no sudoers
    exists on a non-Linux host-like layout? Missing /etc/sudoers is treated as
    not a finding by returning [].
    """
    paths = []
    try:
        if not os.path.exists(SUDOERS_PATH):
            return []
        with open(SUDOERS_PATH, "r", encoding="utf-8", errors="replace") as f:
            main_text = f.read()
    except OSError:
        return None

    texts = [(SUDOERS_PATH, main_text)]
    for inc in _sudoers_includes(main_text):
        try:
            with open(inc, "r", encoding="utf-8", errors="replace") as f:
                texts.append((inc, f.read()))
        except OSError:
            # unreadable include: return None? better mark unknown overall
            return None

    rules = []
    for source, text in texts:
        rules.extend(_parse_sudoers_rules(text, source, now=now))
    return rules


def _parse_ss_listeners(output: str) -> list[dict]:
    listeners = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        # ss -tulpnH: Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
        proto = parts[0].lower()
        if proto not in {"tcp", "udp"}:
            continue
        local = parts[4]
        if ":" not in local:
            continue
        addr, port = local.rsplit(":", 1)
        addr = addr.strip("[]")
        if addr.startswith("%", 0):
            pass
        # strip zone id
        if "%" in addr:
            addr = addr.split("%", 1)[0]
        # process field like users:(("name",pid=...,fd=...))
        process = ""
        m = re.search(r'users:\(\("([^"]+)"', line)
        if m:
            process = m.group(1)
        try:
            port_i = int(port)
        except ValueError:
            continue
        listeners.append({
            "address": addr,
            "port": port_i,
            "proto": proto,
            "process": process,
        })
    # dedupe
    seen = set()
    out = []
    for l in listeners:
        key = (l["address"], l["port"], l["proto"], l["process"])
        if key in seen:
            continue
        seen.add(key)
        out.append(l)
    return out


def _proc_ip(hex_address: str, is_ipv6: bool) -> str:
    """Decode /proc/net's hex address (host byte order) into dotted/quad notation."""
    raw = bytes.fromhex(hex_address)
    if not is_ipv6:
        return socket.inet_ntop(socket.AF_INET, raw[::-1])
    # IPv6 is printed as eight little-endian 32-bit words.
    ordered = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
    return socket.inet_ntop(socket.AF_INET6, ordered)


def _parse_proc_net_listeners(proc_root: Path | None = None) -> list[dict]:
    """Read LISTEN sockets from /proc/net/{tcp,tcp6,udp,udp6}.

    A last-resort reader for hosts without iproute2. It returns the same shape
    as :func:`_parse_ss_listeners`, with an empty process name: /proc does not
    tell us which binary owns a socket without an inode-to-fd lookup, and a
    guess would be worse than an honest blank.
    """
    root = proc_root if proc_root is not None else PROC_ROOT
    listeners = []
    for proto, tables in (("tcp", ("tcp", "tcp6")), ("udp", ("udp", "udp6"))):
        for table in tables:
            try:
                text = (root / table).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for line in text.splitlines()[1:]:
                parts = line.split()
                if len(parts) < 4 or ":" not in parts[1]:
                    continue
                if proto == "tcp" and parts[3] != "0A":  # TCP_LISTEN
                    continue
                hex_addr, hex_port = parts[1].rsplit(":", 1)
                try:
                    port = int(hex_port, 16)
                    address = _proc_ip(hex_addr, table.endswith("6"))
                except (ValueError, OSError):
                    continue
                listeners.append({
                    "address": address,
                    "port": port,
                    "proto": proto,
                    "process": "",
                })
    seen = set()
    out = []
    for listener in listeners:
        key = (listener["address"], listener["port"], listener["proto"])
        if key in seen:
            continue
        seen.add(key)
        out.append(listener)
    return out


def listening_ports() -> list[dict] | None:
    """Return listening TCP/UDP sockets.

    Prefers `ss -tulpnH`; falls back to /proc/net when `ss` is missing or
    fails. ``None`` means *both* sources were unavailable, which the check
    reports as an unknown rather than as a clean host. Process names may be
    missing without root; sockets are still reported.
    """
    try:
        done = _run(["ss", "-tulpnH"])
    except (OSError, subprocess.SubprocessError):
        done = None
    if done is not None and done.returncode == 0:
        return _parse_ss_listeners(done.stdout)
    return _parse_proc_net_listeners() or None


def reboot_required_markers() -> list[str]:
    """Return reboot-required marker files that exist.

    Missing files mean no finding; unreadable existing files are still reported
    as present by path (caller can treat as signal). This is intentionally
    narrow and cross-distro best-effort.
    """
    found = []
    for path in REBOOT_REQUIRED_PATHS:
        try:
            if os.path.exists(path):
                found.append(path)
        except OSError:
            continue
    return found


def sensitive_runtime_dirs() -> list[str]:
    """Return existing sensitive runtime dirs to scan (bounded, explicit)."""
    found = []
    for path in SENSITIVE_RUNTIME_DIRS:
        try:
            if os.path.isdir(path):
                found.append(path)
        except OSError:
            continue
    return found


def sensitive_runtime_world_writable(dirs: list[str] | None = None) -> tuple[list[dict], list[dict]]:
    """Find world-writable entries in sensitive runtime dirs.

    Bounded scan: top-level entries only (no recursive walk) to avoid noise and
    load on large dirs. Returns (records, errors).
    Each record: {path, mode, is_dir}. Errors: {path, error}.
    Missing dirs are ignored (no finding).
    """
    records = []
    errors = []
    for base in (dirs or sensitive_runtime_dirs()):
        try:
            if not os.path.exists(base):
                continue
            with os.scandir(base) as it:
                for entry in it:
                    try:
                        st = entry.stat(follow_symlinks=False)
                    except OSError as exc:
                        errors.append({"path": entry.path, "error": str(exc)})
                        continue
                    mode = st.st_mode
                    if mode & 0o002:
                        records.append({
                            "path": entry.path,
                            "mode": oct(mode & 0o777),
                            "is_dir": entry.is_dir(follow_symlinks=False),
                        })
        except OSError as exc:
            errors.append({"path": base, "error": str(exc)})
    return records, errors
