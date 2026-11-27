"""Individual health and safety checks.

Each check takes a snapshot of host state and returns a list of Finding. A
check that finds nothing returns an empty list rather than None, so callers can
concatenate results without guarding.
"""

import ipaddress
import os
import re

from .collector import normalize_release
from .finding import Finding
from .severity import Severity

# Backend states that mean the node is not usable on the tailnet.
_BAD_BACKEND_STATES = {"NeedsLogin", "Stopped", "NoState", "Starting"}


def tailscale_check(status: dict) -> list:
    """Report problems with this node's Tailscale membership.

    ``status`` is the parsed ``tailscale status --json`` payload. Only the
    fields this check reads are required; a missing key is treated as unknown
    rather than as a healthy value.
    """
    findings = []

    state = status.get("BackendState")
    if state in _BAD_BACKEND_STATES:
        findings.append(
            Finding(
                check="tailscale.backend",
                severity=Severity.CRITICAL,
                message=f"Tailscale backend state is {state!r}, not Running",
                remedy="Run `tailscale up` and complete the browser login.",
                evidence={"backend_state": state},
            )
        )

    return findings


def tailscale_ssh_check(status: dict | None) -> list:
    """Report when Tailscale SSH is enabled on this node.

    Tailscale SSH can be a deliberate access path, but it changes the SSH trust
    boundary. We report it as INFO for visibility; disabled or unknown is no
    finding.
    """
    if not isinstance(status, dict):
        return []
    self_node = status.get("Self")
    if not isinstance(self_node, dict):
        return []
    run_ssh = self_node.get("RunSSH")
    if run_ssh is not True:
        return []
    return [
        Finding(
            check="tailscale.ssh_enabled",
            severity=Severity.INFO,
            message="Tailscale SSH is enabled on this node",
            remedy="If unintended, disable Tailscale SSH in tailnet ACL/policy or via `tailscale set --ssh=false` as appropriate.",
            evidence={"enabled": True, "source": "status.Self.RunSSH"},
        )
    ]


def _is_private_source(source: str) -> bool:
    """Return True when a firewall source cannot reach the host from the internet.

    Accepts a bare address or a CIDR. ``Anywhere`` and an empty value are not
    private, and neither is anything unparseable — an unrecognised source must
    fail closed rather than be assumed safe.

    This is deliberately based on ``is_global`` rather than ``is_private``.
    In Python 3.14 ``is_private`` is True for the documentation ranges
    (``192.0.2.0/24``, ``198.51.100.0/24``, ``203.0.113.0/24``), which are not
    reachable from a hostile network but are also not a trusted source. The
    auditor's question is the opposite one: *can this source reach me from the
    internet?* ``is_global`` answers it directly.
    """
    text = (source or "").strip()
    if not text or text.lower() == "anywhere":
        return False
    try:
        if "/" in text:
            addr = ipaddress.ip_network(text, strict=False).network_address
        else:
            addr = ipaddress.ip_address(text)
    except ValueError:
        return False

    return not addr.is_global


def ssh_exposure_check(rules: list | None, default_incoming: str | None = "deny") -> list:
    """Report SSH reachable from anything other than the tailnet.

    ``rules`` is a list of parsed firewall rules. Each rule is a dict with
    ``port``, ``action`` and ``interface`` keys; an empty ``interface`` means
    the rule applies to every interface, which is what makes SSH exposed.

    ``rules`` is ``None`` when the firewall could not be read — the tool is
    missing, or it failed, which on Arch/Omarchy is every unprivileged run.
    That is reported rather than treated as "no rules": a check that could not
    read its input has not passed.

    ``default_incoming`` is the firewall's default policy for incoming traffic.
    When it is ``allow`` and nothing restricts port 22, SSH is exposed by
    omission; when it is ``deny``, an unmentioned port is closed and there is
    nothing to report. ``None`` means the policy could not be read either.
    """
    findings = []

    if rules is None or default_incoming is None:
        findings.append(
            Finding(
                check="sshd.firewall_unreadable",
                severity=Severity.WARNING,
                message="The firewall state could not be read, so SSH exposure is unknown",
                remedy=(
                    "Run as root, or allow `ufw status verbose` through polkit. "
                    "See the privileges table in the README."
                ),
                evidence={"rules": rules, "default_incoming": default_incoming},
            )
        )
        return findings

    ssh_rules = [r for r in rules if str(r.get("port", "")).startswith("22")]

    if not ssh_rules:
        if default_incoming == "allow":
            findings.append(
                Finding(
                    check="sshd.unrestricted",
                    severity=Severity.WARNING,
                    message="No firewall rule mentions port 22 and the default policy allows incoming traffic",
                    remedy="Add an explicit allow for 22/tcp on tailscale0 and a deny elsewhere.",
                    evidence={"ssh_rules": ssh_rules, "default_incoming": default_incoming},
                )
            )
        return findings

    for rule in ssh_rules:
        if rule.get("action") != "ALLOW":
            continue
        if not rule.get("interface") and not _is_private_source(rule.get("source", "")):
            findings.append(
                Finding(
                    check="sshd.exposed",
                    severity=Severity.CRITICAL,
                    message="SSH is allowed on every interface, including the public one",
                    remedy="Allow 22/tcp on tailscale0 only, and deny it on other interfaces.",
                    evidence={"rule": rule},
                )
            )

    return findings


def pending_updates_check(count: int | None) -> list:
    """Report a host with pending package updates.

    ``None`` means the auditor could not determine the answer — no package
    manager it knows, or the command failed. Unknown is not a finding.

    The thresholds are a starting point: 1–20 is routine, 21–100 is falling
    behind, over 100 suggests the host is not being maintained at all.
    """
    if count is None or count == 0:
        return []

    if count > 100:
        severity = Severity.CRITICAL
    elif count > 20:
        severity = Severity.WARNING
    else:
        severity = Severity.INFO

    return [
        Finding(
            check="packages.outdated",
            severity=severity,
            message=f"{count} package update(s) are pending",
            remedy="Review and apply pending updates (`pacman -Syu` on Arch).",
            evidence={"pending": count},
        )
    ]


def clock_check(state: dict) -> list:
    """Report a host whose clock is not being synchronised.

    ``state`` comes from :func:`collector.clock_state`. ``None`` means it could
    not be read, and unknown is not a finding: a host with no timedatectl is
    not a host with a broken clock.
    """
    if state.get("synchronised") is False or state.get("service_active") is False:
        return [
            Finding(
                check="time.unsynchronised",
                severity=Severity.WARNING,
                message="The host's clock is not being synchronised",
                remedy="Enable systemd-timesyncd (`systemctl enable --now systemd-timesyncd`).",
                evidence={
                    "synchronised": state.get("synchronised"),
                    "service_active": state.get("service_active"),
                },
            )
        ]
    return []


def auditor_degraded_check(errors: dict) -> list:
    """Report readers that could not run.

    ``errors`` comes from :func:`collector.collector_errors`. An empty map means
    every reader answered and the report can be trusted. A non-empty one means
    the audit saw less than it should, and the findings it did produce are
    incomplete — so that has to be visible rather than folded into silence.
    """
    if not errors:
        return []

    return [
        Finding(
            check="auditor.degraded",
            severity=Severity.WARNING,
            message=(
                f"{len(errors)} reader(s) could not run, so this report is incomplete: "
                + ", ".join(f"{name} ({errors[name]['reason']})" for name in sorted(errors))
            ),
            remedy="Install the missing tools, or run the auditor as root where a reader needs it.",
            evidence={
                "readers": {name: error["reason"] for name, error in errors.items()},
                "errors": [errors[name] for name in sorted(errors)],
            },
        )
    ]


def tailscale_exposure_check(services: list) -> list:
    """Report a local service published beyond the tailnet.

    ``services`` comes from :func:`collector.tailscale_services`: one dict per
    published port with ``service``, ``port`` and ``target``. A funnel to the
    internet bypasses the host firewall entirely, which makes it the same class
    of problem as ``sshd.exposed`` one layer up.
    """
    findings = []

    for service in services:
        if service.get("target") != "internet":
            continue
        port = service.get("port", "?")
        findings.append(
            Finding(
                check="tailscale.exposed",
                severity=Severity.CRITICAL,
                message=(
                    f"Port {port} is published to the internet with tailscale funnel, "
                    "bypassing the host firewall"
                ),
                remedy="Remove the funnel (`tailscale funnel off`) or replace it with `tailscale serve`.",
                evidence={"service": service.get("service"), "port": port},
            )
        )

    for service in services:
        if service.get("target") != "tailnet":
            continue
        findings.append(
            Finding(
                check="tailscale.published",
                severity=Severity.INFO,
                message=(
                    f"Port {service.get('port', '?')} is published to the tailnet with tailscale serve"
                ),
                remedy="",
                evidence={"service": service.get("service"), "port": service.get("port")},
            )
        )

    return findings


def sshd_config_check(config: dict | None) -> list:
    """Report an sshd configuration that accepts weak authentication.

    ``config`` carries the effective values read by :func:`collector.sshd_config`.
    ``None`` for either setting means it could not be read, and an unknown value
    is not a finding: this check reports what the daemon would accept, not what
    the auditor failed to see.
    """
    if config is None:
        return []

    findings = []

    if config.get("permit_root_login") is True:
        findings.append(
            Finding(
                check="sshd.root_login",
                severity=Severity.CRITICAL,
                message="sshd accepts a root login",
                remedy="Set `PermitRootLogin no` (or `prohibit-password`) in /etc/ssh/sshd_config.",
                evidence={"permit_root_login": True},
            )
        )

    if config.get("password_authentication") is True:
        findings.append(
            Finding(
                check="sshd.password_auth",
                severity=Severity.WARNING,
                message="sshd accepts password authentication",
                remedy="Set `PasswordAuthentication no` and rely on keys, which is the point of a tailnet-only host.",
                evidence={"password_authentication": True},
            )
        )

    return findings


def power_restore_check(state: dict) -> list:
    """Report a machine that would stay dark after a power cut.

    Intel Macs of the Mac mini 2012 era keep the "power on when AC returns"
    behaviour in a volatile chipset register: firmware clears it on every
    power cycle, so a boot-time unit must rewrite it. ``state`` carries what
    the auditor read: ``present`` (the register could be read), ``register``
    (its value) and ``unit_enabled`` (whether that unit is enabled).
    """
    findings = []

    if not state.get("present"):
        findings.append(
            Finding(
                check="power.register_missing",
                severity=Severity.WARNING,
                message="The power-restore register could not be read on this machine",
                remedy="Confirm the LPC device path exists; this check only applies to Intel Macs.",
                evidence={"present": False},
            )
        )
        return findings

    register = state.get("register")
    if register is None:
        return findings

    # setpci prints 0xff when it cannot open the device, which is an access
    # failure rather than a register value. Treating it as a value would raise
    # a false critical finding on every unprivileged run.
    if register == 0xFF:
        findings.append(
            Finding(
                check="power.register_unreadable",
                severity=Severity.WARNING,
                message="The power-restore register could not be read (setpci reported 0xff)",
                remedy="Run the auditor as root, or grant the user access to the PCI config space.",
                evidence={"register": register},
            )
        )
        return findings

    if register & 0x01:
        findings.append(
            Finding(
                check="power.restore_disabled",
                severity=Severity.CRITICAL,
                message="The chipset is set to stay off when power returns",
                remedy="Run `setpci -s 00:1f.0 0xa4.b=0:1` and enable the boot unit that rewrites it.",
                evidence={"register": register},
            )
        )

    if state.get("unit_enabled") is False:
        findings.append(
            Finding(
                check="power.unit_disabled",
                severity=Severity.WARNING,
                message="The boot unit that restores auto power-on is not enabled",
                remedy="Run `systemctl enable mac-mini-power-restore.service`.",
                evidence={"unit_enabled": False},
            )
        )
    elif state.get("unit_enabled") is True and state.get("unit_active") is False:
        findings.append(
            Finding(
                check="power.unit_failed",
                severity=Severity.CRITICAL,
                message="The boot unit that restores auto power-on is enabled but did not run successfully",
                remedy=(
                    "Check `systemctl status mac-mini-power-restore.service` and its journal: "
                    "a failed ConditionPathExists or a setpci error leaves the register unwritten."
                ),
                evidence={"unit_enabled": True, "unit_active": False},
            )
        )

    return findings


# Disk thresholds. pacman and sshd both have to write to serve a session, and
# a host that cannot write stops looking like a host with a network problem,
# which is the fault this tool exists to separate from the others.
DISK_WARNING_PERCENT = 90
DISK_CRITICAL_PERCENT = 95
DISK_INODE_WARNING_PERCENT = 95
DISK_INODE_CRITICAL_PERCENT = 99


def disk_space_check(usage: dict | None) -> list:
    """Report a filesystem running out of bytes or of inodes.

    ``usage`` comes from :func:`collector.disk_usage`. ``None`` means it could
    not be read, which is not a finding: a host whose root filesystem cannot
    be statvfs'd is not a host with a full disk.

    The two sides are checked separately and the worse one wins, because they
    can disagree: inodes can be gone with terabytes still free.
    """
    if usage is None:
        return []

    percent = usage["percent_used"]
    inode_percent = usage["inode_percent_used"]

    if percent >= DISK_CRITICAL_PERCENT or inode_percent >= DISK_INODE_CRITICAL_PERCENT:
        severity = Severity.CRITICAL
    elif percent >= DISK_WARNING_PERCENT or inode_percent >= DISK_INODE_WARNING_PERCENT:
        severity = Severity.WARNING
    else:
        return []

    which = "inodes" if inode_percent > percent else "space"
    return [
        Finding(
            check="disk.space_low",
            severity=severity,
            message=(
                f"The root filesystem is {percent:.1f}% full and "
                f"{inode_percent:.1f}% of its inodes are used"
            ),
            remedy=(
                "Free space before anything else: `du -xhd1 /` to find what "
                "grew, then clean package caches and old logs. If inodes are "
                "the tight side, a directory of small files is the cause, not "
                "a large one. Do not fill it further."
            ),
            evidence={
                "percent_used": percent,
                "inode_percent_used": inode_percent,
                "free": usage["free"],
                "total": usage["total"],
            },
        )
    ]


# Losing one of these makes the host unreachable or unmanageable: a dead sshd
# on a machine you reach only over the network is the outage itself, not a
# symptom. Matched by substring so `ssh.service` and `sshd.service` both hit,
# and so a distro's name variant does not slip through.
CRITICAL_FAILED_UNITS = (
    "sshd.service",
    "ssh.service",
    "tailscaled.service",
    "networkmanager.service",
    "systemd-networkd.service",
    "ufw.service",
)


def failed_units_check(units: list | None) -> list:
    """Report systemd units whose last run failed.

    ``units`` comes from :func:`collector.failed_units`. ``None`` means the
    question could not be asked, which is not a finding: a host with no
    systemctl is not a host with a failed service.

    A unit whose loss makes the host unreachable is critical; any other failed
    unit is a warning, because it is still worth knowing and still not an
    emergency.
    """
    if not units:
        return []

    names = [u["name"] for u in units]
    critical = [
        n for n in names
        if any(c in n.lower() for c in CRITICAL_FAILED_UNITS)
    ]
    severity = Severity.CRITICAL if critical else Severity.WARNING
    worst = critical or names
    return [
        Finding(
            check="systemd.failed",
            severity=severity,
            message=(
                f"{len(names)} systemd unit(s) failed"
                + (f", including {', '.join(worst)}" if critical else "")
            ),
            remedy=(
                "`systemctl status <unit>` and `journalctl -u <unit> -b` to see "
                "why. If the unit is one whose loss makes the host "
                "unreachable, that is the outage: restart it and find the "
                "cause, do not just restart and move on."
            ),
            evidence={"units": names, "critical": critical},
        )
    ]


def _version_key(release: str) -> tuple:
    """``7.2.15-1`` -> ``(7, 2, 15, 1)``, for a numeric comparison.

    Comparison, not equality: the question is whether the installed kernel is
    newer, and a string compare would call ``7.2.9`` newer than ``7.2.15``.
    Reading stops at the first non-numeric part, so a suffix cannot make the
    tuple longer and win.
    """
    key = []
    for part in re.split(r"[.-]", release):
        digits = re.match(r"\d+", part)
        if not digits:
            break
        key.append(int(digits.group(0)))
    return tuple(key)


def is_pending_kernel_boot(running: str, installed: list) -> bool:
    """Whether the running kernel is older than the newest installed one.

    ``running`` is ``uname -r`` and may carry the distro suffix;
    ``installed`` is a list of package versions. An empty list is False: a host
    with no kernel package to compare against is not a host waiting on a
    restart.
    """
    if not installed:
        return False
    running_key = _version_key(normalize_release(running))
    newest_key = max(_version_key(v) for v in installed)
    return newest_key > running_key


def kernel_reboot_check(versions: dict | None) -> list:
    """Report a kernel newer than the running one.

    ``versions`` comes from :func:`collector.kernel_versions`. ``None`` means it
    could not be read, which is not a finding: a host with no ``uname`` is not a
    host with a stale kernel.

    The scenario that makes this matter is the one this tool exists for: the
    host is updated, then loses power, then boots the old kernel with every fix
    that shipped in the new one absent -- while ``packages.outdated`` reads 0,
    because the update is installed.
    """
    if versions is None or not versions.get("installed"):
        return []
    if not is_pending_kernel_boot(versions["running"], versions["installed"]):
        return []

    newest = max(versions["installed"], key=_version_key)
    return [
        Finding(
            check="kernel.pending_reboot",
            severity=Severity.WARNING,
            message=(
                f"The running kernel is {versions['running']} but "
                f"{newest} is installed; a restart is needed to run it"
            ),
            remedy=(
                "Restart the host when you can. Until then it is running the "
                "previous kernel, so anything that shipped in the new one is "
                "not in effect -- and on a host that loses power, that is what "
                "comes back."
            ),
            evidence={
                "running": versions["running"],
                "installed": versions["installed"],
                "newest": newest,
            },
        )
    ]


# An orphan that is a kernel or something the boot path loads is worth more
# than housekeeping: removing it by hand is where a machine stops booting.
# Matched as a prefix so `linux-lts`, `linux-zen` and a vendor kernel all hit.
ORPHAN_WARNING_PREFIXES = (
    "linux",
    "nvidia",
    "zram",
    "mkinitcpio",
    "grub",
    "systemd",
)


def orphaned_packages_check(orphans: list | None) -> list:
    """Report installed packages nothing requires any more.

    ``orphans`` comes from :func:`collector.orphaned_packages`. ``None`` means
    the question could not be asked (no pacman), which is not a finding: a host
    with no pacman is not a host with a clean dependency tree.

    Orphans are info -- housekeeping, not an emergency. An orphan that looks
    like a kernel or a boot-path package is a warning, because those are the
    ones where removing them wrong stops the next boot.
    """
    if not orphans:
        return []

    names = [o["name"] for o in orphans]
    heavy = [
        n for n in names
        if any(n.startswith(prefix) for prefix in ORPHAN_WARNING_PREFIXES)
    ]
    severity = Severity.WARNING if heavy else Severity.INFO
    return [
        Finding(
            check="packages.orphaned",
            severity=severity,
            message=(
                f"{len(names)} installed package(s) nothing requires"
                + (f", including {', '.join(heavy)}" if heavy else "")
            ),
            remedy=(
                "`pacman -Qdt` to see them again, then `pacman -Rns <pkg>` "
                "after checking what it would take with it (`-Rns` removes the "
                "dependencies that came with it; read the list first). Never "
                "remove a kernel or a boot-path package without knowing which "
                "one the host boots."
            ),
            evidence={"packages": names, "boot_path": heavy},
        )
    ]


def empty_password_accounts_check(accounts: list | None) -> list:
    """Report accounts that can authenticate with no password.

    ``accounts`` comes from :func:`collector.empty_password_accounts`. ``None``
    means the database existed but could not be read: that is a warning about
    the audit's coverage, not a finding about the host, and it must not be
    reported as a clean database. An empty list is a clean answer.
    """
    if accounts is None:
        return [
            Finding(
                check="security.shadow_unreadable",
                severity=Severity.WARNING,
                message="The account database could not be read, so passwordless accounts are unknown",
                remedy="Run the auditor as root, or grant read access to /etc/shadow.",
                evidence={"path": "/etc/shadow"},
            )
        ]

    names = [account["name"] for account in accounts]
    if not names:
        return []

    return [
        Finding(
            check="security.empty_password_accounts",
            severity=Severity.CRITICAL,
            message=(
                f"{len(names)} account(s) have an empty password hash: "
                + ", ".join(names)
            ),
            remedy=(
                "Set a password (`passwd <user>`) or lock the account "
                "(`usermod -L <user>`). An empty field means login with no "
                "password for any service that honours /etc/shadow."
            ),
            evidence={"accounts": names},
        )
    ]


# The only account allowed to have UID 0. Service placeholders keep their own
# UIDs; anything else at UID 0 is a second root account.
UID0_ALLOWLIST = {"root"}


def uid0_accounts_check(accounts: list | None) -> list:
    """Report every account with UID 0 besides ``root``.

    ``accounts`` comes from :func:`collector.uid0_accounts`. ``None`` means the
    database existed but could not be read: that is a coverage warning, not a
    clean host. Each finding names one account and carries only the four
    non-sensitive fields the reader returned.
    """
    if accounts is None:
        return [
            Finding(
                check="security.passwd_unreadable",
                severity=Severity.WARNING,
                message="The account database could not be read, so UID 0 accounts are unknown",
                remedy="Run the auditor as root, or grant read access to /etc/passwd.",
                evidence={"path": "/etc/passwd"},
            )
        ]

    findings = []
    for account in accounts:
        name = account.get("name", "")
        if name in UID0_ALLOWLIST:
            continue
        findings.append(Finding(
            check="security.uid0_account",
            severity=Severity.CRITICAL,
            message=f"Account {name!r} also has UID 0, giving it full root privileges",
            remedy=(
                "Delete the account (`userdel <name>`) or assign it a new unique "
                "UID (`usermod -u <new-uid> <name>`) and fix file ownership "
                "afterwards. A second UID 0 account is a common persistence path."
            ),
            evidence={
                "name": name,
                "uid": account.get("uid"),
                "home": account.get("home"),
                "shell": account.get("shell"),
            },
        ))
    return findings


def config_drift_check(drift: dict | None) -> list:
    """Report config files pacman left behind for an administrator to review.

    ``drift`` comes from :func:`collector.config_drift`. ``None`` means the
    scan could not complete; that is a finding about the audit's coverage, not
    a clean tree. The evidence is capped so a mass replacement cannot flood
    the report; ``counts`` always carries the real totals.
    """
    if drift is None:
        return [
            Finding(
                check="config.drift_unknown",
                severity=Severity.WARNING,
                message="The /etc scan could not be completed, so replaced config files are unknown",
                remedy="Run the auditor as root, or grant read access to /etc.",
                evidence={"path": "/etc"},
            )
        ]

    pacnew = drift.get("pacnew", [])
    pacsave = drift.get("pacsave", [])
    total = len(pacnew) + len(pacsave)
    if not total:
        return []

    shown = [*pacnew[:10], *pacsave[:10]]
    suffix = "" if total <= len(shown) else f" (and {total - len(shown)} more)"
    return [
        Finding(
            check="config.drift",
            severity=Severity.WARNING,
            message=(
                f"{total} replaced config file(s) need review: "
                + ", ".join(shown)
                + suffix
            ),
            remedy=(
                "Review each with `pacdiff` and its owning package with "
                "`pacman -Qo`, then keep or remove it. Do not delete blindly."
            ),
            evidence={
                "pacnew": pacnew[:20],
                "pacsave": pacsave[:20],
                "counts": {"pacnew": len(pacnew), "pacsave": len(pacsave)},
                "truncated": drift.get("truncated", False),
            },
        )
    ]


# Directories whose write bit turns into root: SSH host keys and config,
# sudo rules, PAM, systemd units and cron drop-ins. A file named *like* one of
# these (`sshd_config` at the top level) is not under it and stays a warning.
_CRITICAL_DIRS = {"ssh", "sudoers.d", "pam.d"}


def _critical_world_writable(path: str) -> bool:
    parts = path.replace("\\", "/").split("/")
    first = parts[0]
    if first in _CRITICAL_DIRS or first.startswith("cron.d"):
        return True
    return first == "systemd" and len(parts) > 2 and parts[1] == "system"


# Evidence cap: a hostile mass-change must not flood the report.
MAX_WORLD_WRITABLE_ENTRIES = 20


def world_writable_etc_check(paths: list | None) -> list:
    """Report world-writable files and directories under /etc.

    ``None`` means the scan could not complete, which is an unknown state, not
    a clean tree. The evidence is capped so a mass change cannot flood a report.
    """
    if paths is None:
        return [
            Finding(
                check="config.world_writable_unknown",
                severity=Severity.WARNING,
                message="The /etc scan could not be completed, so world-writable paths are unknown",
                remedy="Run the auditor as root, or grant read access to /etc.",
                evidence={"path": "/etc"},
            )
        ]
    if not paths:
        return []

    shown = paths[:MAX_WORLD_WRITABLE_ENTRIES]
    suffix = (
        ""
        if len(paths) <= len(shown)
        else f" (and {len(paths) - len(shown)} more)"
    )
    names = ", ".join(item["path"] for item in shown)
    critical = any(_critical_world_writable(item["path"]) for item in paths)
    return [
        Finding(
            check="config.world_writable",
            severity=Severity.CRITICAL if critical else Severity.WARNING,
            message=f"{len(paths)} world-writable path(s) under /etc: {names}{suffix}",
            remedy="Remove the write bit for others (`chmod o-w PATH`) and investigate who can write there.",
            evidence={"paths": shown, "total": len(paths)},
        )
    ]


def firewall_default_check(default_incoming: str | None) -> list:
    """Report an incoming firewall policy that allows traffic by default.

    ``None`` means the policy could not be read; ``sshd.firewall_unreadable``
    already owns that unknown state, so this check stays silent. ``allow`` is
    critical. ``deny`` and ``reject`` are safe defaults. Anything else readable
    is reported as a warning because the auditor cannot classify it.
    """
    if default_incoming in (None, "deny", "reject"):
        return []
    if default_incoming == "allow":
        return [
            Finding(
                check="firewall.default_allow",
                severity=Severity.CRITICAL,
                message="The firewall default incoming policy is allow, so services are reachable by default",
                remedy="Set `ufw default deny incoming`, then allow only the ports you need.",
                evidence={"default_incoming": default_incoming},
            )
        ]
    return [
        Finding(
            check="firewall.default_allow",
            severity=Severity.WARNING,
            message=(
                f"The firewall default incoming policy is {default_incoming!r}, which this auditor cannot classify as safe"
            ),
            remedy="Set `ufw default deny incoming`, then allow only the ports you need.",
            evidence={"default_incoming": default_incoming},
        )
    ]


def firewall_disabled_check(active: bool | None) -> list:
    """Report an explicitly disabled/inactive UFW firewall.

    ``None`` means the state could not be read; unknown is not a finding and
    the unreadable firewall state is reported elsewhere. Only the positive
    "disabled" case is reported here.
    """
    if active is not False:
        return []
    return [
        Finding(
            check="firewall.disabled",
            severity=Severity.CRITICAL,
            message="The UFW firewall is inactive, so incoming connections are not filtered by host firewall rules",
            remedy="Review your rules, then enable UFW (`ufw enable`). Verify remote access first to avoid lockout.",
            evidence={"active": False},
        )
    ]


def _mode_bits(mode: str | None) -> int | None:
    if not mode:
        return None
    try:
        return int(mode, 8)
    except ValueError:
        return None


def _infer_sensitive_kind(record: dict) -> str:
    kind = record.get("kind", "")
    if kind:
        return kind
    path = record.get("path", "")
    expected = record.get("expected", "")
    if path.endswith("/crypto_keyfile.bin") or "0400 root-owned" == expected and "keyfile" in path:
        return "luks_keyfile"
    if "/ssh_host_" in path and path.endswith("_key"):
        return "ssh_host_private_key"
    if "/.ssh/id_" in path and not path.endswith(".pub"):
        return "ssh_user_private_key"
    if path.endswith("/docker.sock"):
        return "docker_sock"
    if path.endswith("tailscaled.state"):
        return "tailscale_state"
    if path.endswith("/.docker/config.json"):
        return "container_credential"
    if (
        path.endswith("/.aws/credentials")
        or path.endswith("application_default_credentials.json")
        or path.endswith("/.kube/config")
    ):
        return "cloud_credential"
    if expected == "0400 root-owned":
        return "luks_keyfile"
    if expected == "0600 root-owned":
        return "ssh_host_private_key"
    return ""


def _sensitive_violation(record: dict) -> tuple[Severity, str] | None:
    mode = _mode_bits(record.get("mode"))
    kind = _infer_sensitive_kind(record)
    uid = record.get("uid")
    if mode is None:
        return None

    world_readable = bool(mode & 0o004)
    world_writable = bool(mode & 0o002)
    group_readable = bool(mode & 0o040)
    group_writable = bool(mode & 0o020)

    if kind == "luks_keyfile":
        if mode != 0o400 or uid != 0:
            return Severity.CRITICAL, "LUKS keyfile must be 0400 and root-owned"
        return None
    if kind == "ssh_host_private_key":
        if mode & 0o077 or uid != 0:
            return Severity.CRITICAL, "SSH host private key must be 0600 and root-owned"
        return None
    if kind == "ssh_user_private_key":
        if mode & 0o077:
            return Severity.CRITICAL, "SSH user private key must be 0600"
        return None
    if kind == "cloud_credential":
        if mode & 0o077:
            return Severity.CRITICAL, "Cloud credential must be 0600"
        return None
    if kind == "container_credential":
        if mode & 0o077:
            return Severity.WARNING, "Container registry credential should be 0600"
        return None
    if kind == "docker_sock":
        if world_readable or world_writable or group_writable or mode & 0o001:
            return Severity.CRITICAL, "Docker socket must not be world-accessible or group-writable"
        if mode != 0o660 and (group_readable or group_writable):
            return Severity.WARNING, "Docker socket should be 0660 root:docker or stricter"
        return None
    if kind == "tailscale_state":
        if world_readable or world_writable:
            return Severity.CRITICAL, "Tailscale state must not be world-readable"
        if group_readable or group_writable:
            return Severity.WARNING, "Tailscale state should not be group-accessible"
        return None
    if world_readable or world_writable:
        return Severity.WARNING, "Sensitive path should not be world-accessible"
    return None


def sensitive_path_permissions_check(records: list[dict] | None) -> list:
    """Report dangerous permissions on a small allowlist of sensitive paths.

    Missing paths are not findings. Unreadable existing paths produce an
    unknown-state warning scoped to this check. Evidence never includes file
    contents.
    """
    if not records:
        return []

    bad = []
    unknown = []
    for rec in records:
        if not rec.get("exists"):
            continue
        if not rec.get("readable"):
            unknown.append(rec)
            continue
        violation = _sensitive_violation(rec)
        if violation is None:
            continue
        severity, reason = violation
        bad.append((severity, reason, rec))

    findings = []
    if bad:
        severity = Severity.CRITICAL if any(s is Severity.CRITICAL for s, _, _ in bad) else Severity.WARNING
        evidence_paths = [{
            "path": r.get("path"),
            "mode": r.get("mode"),
            "uid": r.get("uid"),
            "gid": r.get("gid"),
            "owner": r.get("owner"),
            "group": r.get("group"),
            "expected": r.get("expected"),
            "reason": reason,
        } for severity_item, reason, r in bad]
        names = ", ".join(r.get("path", "?") for _, _, r in bad)
        findings.append(Finding(
            check="security.sensitive_path_permissions",
            severity=severity,
            message=f"Sensitive local path(s) have unsafe permissions: {names}",
            remedy=(
                "Restrict permissions/ownership (e.g. chmod 0400 /crypto_keyfile.bin; "
                "chmod 0600 /etc/ssh/ssh_host_*_key and ~/.ssh/id_*; "
                "chmod 600 ~/.aws/credentials ~/.kube/config ~/.docker/config.json; "
                "chmod 0660 /run/docker.sock root:docker)."
            ),
            evidence={"paths": evidence_paths, "total": len(evidence_paths)},
        ))
    for rec in unknown:
        findings.append(Finding(
            check="security.sensitive_path_unknown",
            severity=Severity.WARNING,
            message=f"Sensitive path exists but could not be read: {rec.get('path')}",
            remedy="Run the auditor with sufficient privileges to stat sensitive paths.",
            evidence={"path": rec.get("path"), "expected": rec.get("expected")},
        ))
    return findings


def passwordless_sudo_check(rules: list[dict] | None) -> list:
    """Report passwordless sudo grants.

    ``None`` means sudoers could not be read (unknown); not a finding here.
    Missing sudoers is represented as [] by collector and is not a finding.
    """
    if not rules:
        return []
    findings = []
    for rule in rules:
        if not rule.get("nopasswd"):
            continue
        commands = str(rule.get("commands", "")).strip()
        expired = bool(rule.get("notafter_expired"))
        critical = commands.upper() == "ALL" and not expired
        severity = Severity.CRITICAL if critical else Severity.WARNING
        notafter = rule.get("notafter")
        deadline = f" (NOTAFTER {notafter}, deadline passed)" if expired and notafter else (f" (NOTAFTER {notafter})" if notafter else "")
        findings.append(Finding(
            check="security.passwordless_sudo",
            severity=severity,
            message=(
                f"Passwordless sudo grant for {rule.get('user', '?')} in {rule.get('file', '?')}: "
                f"NOPASSWD {commands}{deadline}"
            ),
            remedy="Remove or narrow the NOPASSWD rule; require authentication for full sudo where possible.",
            evidence={
                "file": rule.get("file"),
                "user": rule.get("user"),
                "commands": commands,
                "notafter": notafter,
                "expired": expired,
            },
        ))
    return findings


def _listener_is_wide_bind(addr: str) -> bool:
    return addr in {"0.0.0.0", "::", "*"}


def _listener_is_loopback(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).is_loopback
    except ValueError:
        return addr in {"localhost"}


def _listener_is_tailscale(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
        return ip in ipaddress.ip_network("100.64.0.0/10") or ip in ipaddress.ip_network("fd7a:115c:a1e0::/48")
    except ValueError:
        return False


def _port_covered_by_tailscale_only(port: int, proto: str, rules: list[dict]) -> bool:
    token = f"{port}/{proto}"
    token_any = str(port)
    for rule in rules:
        if rule.get("action") != "ALLOW":
            continue
        rp = str(rule.get("port", ""))
        if rp not in {token, token_any}:
            continue
        iface = rule.get("interface", "")
        src = str(rule.get("source", "")).lower()
        if iface == "tailscale0" or "tailscale" in src:
            # if rule is scoped to tailscale interface, consider covered
            return True
    return False


def listener_exposure_check(listeners: list[dict] | None, rules: list[dict] | None, default_incoming: str | None = "deny") -> list:
    """Report non-loopback wide-bind listeners.

    Firewall unreadable => unknown, not silence. Loopback/tailscale-only binds
    are ignored. A wide bind with deny default and no explicit rule is INFO;
    allow default is WARNING. Listeners unreadable => an explicit unknown
    finding, never a clean report.
    """
    if listeners is None:
        return [Finding(
            check="network.listeners_unreadable",
            severity=Severity.WARNING,
            message=(
                "Listening sockets could not be read (no working `ss` and no "
                "/proc/net/tcp*), so network exposure is unknown"
            ),
            remedy="Install iproute2 (ss), or run on a Linux host with /proc mounted.",
            evidence={"source": "listening sockets"},
        )]
    if rules is None or default_incoming is None:
        return [Finding(
            check="network.firewall_unreadable",
            severity=Severity.WARNING,
            message="Firewall state could not be read, so listener exposure is unknown",
            remedy="Run as root or grant access to firewall status commands.",
            evidence={"default_incoming": default_incoming},
        )]
    findings = []
    for l in listeners:
        addr = str(l.get("address", ""))
        port = int(l.get("port", 0))
        proto = str(l.get("proto", "tcp")).lower()
        if port == 22 and proto == "tcp":
            continue  # ssh_exposure_check owns SSH
        if _listener_is_loopback(addr) or _listener_is_tailscale(addr):
            continue
        if not _listener_is_wide_bind(addr):
            continue
        if _port_covered_by_tailscale_only(port, proto, rules):
            continue
        if default_incoming == "allow":
            severity = Severity.WARNING
            msg = f"Listener {proto}/{port} binds {addr} and firewall default allows incoming"
        else:
            severity = Severity.INFO
            msg = f"Listener {proto}/{port} binds {addr}; firewall default denies but port is not explicitly restricted"
        findings.append(Finding(
            check="network.listener_wide_bind",
            severity=severity,
            message=msg,
            remedy="Bind the service to loopback/tailscale interface, or add a firewall rule restricting access (prefer tailscale0).",
            evidence={"address": addr, "port": port, "proto": proto, "process": l.get("process", "")},
        ))
    return findings


def reboot_required_check(markers: list[str] | None) -> list:
    """Report reboot-required marker files present on the host.

    Marker files are used by some distros (e.g. Debian/Ubuntu) to signal that
    a reboot is needed. Missing markers mean no finding.
    """
    if not markers:
        return []
    present = []
    for m in markers:
        try:
            if os.path.exists(str(m)):
                present.append(str(m))
        except OSError:
            continue
    if not present:
        return []
    return [
        Finding(
            check="system.reboot_required",
            severity=Severity.WARNING,
            message=f"Reboot-required marker present: {', '.join(present)}",
            remedy="Schedule a reboot when convenient to apply pending system changes.",
            evidence={"markers": present},
        )
    ]


def sensitive_runtime_world_writable_check(records: list[dict] | None, errors: list[dict] | None = None) -> list:
    """Report world-writable entries in sensitive runtime dirs.

    Bounded/explicit scan; missing dirs yield no findings. Unreadable dirs are
    surfaced as unknown warnings.
    """
    findings = []
    for rec in (records or []):
        path = str(rec.get("path", ""))
        mode = rec.get("mode", "")
        is_dir = bool(rec.get("is_dir"))
        findings.append(Finding(
            check="security.world_writable_sensitive_runtime",
            severity=Severity.CRITICAL,
            message=f"World-writable {'directory' if is_dir else 'file'} in sensitive runtime path: {path}",
            remedy="Restrict permissions (remove world-writable bit) and investigate why it was writable.",
            evidence={"path": path, "mode": mode, "is_dir": is_dir},
        ))
    for err in (errors or []):
        findings.append(Finding(
            check="security.sensitive_runtime_unknown",
            severity=Severity.WARNING,
            message=f"Could not inspect sensitive runtime path: {err.get('path', '')}",
            remedy="Run with sufficient privileges to inspect sensitive runtime directories.",
            evidence={"path": err.get("path", ""), "error": err.get("error", "")},
        ))
    return findings
