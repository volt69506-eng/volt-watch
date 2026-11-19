"""Individual health and safety checks.

Each check takes a snapshot of host state and returns a list of Finding. A
check that finds nothing returns an empty list rather than None, so callers can
concatenate results without guarding.
"""

import ipaddress

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

    return findings
