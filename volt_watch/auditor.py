"""Run every check against the live host and collect the findings."""

from . import collector
from .checks import (
    auditor_degraded_check,
    clock_check,
    config_drift_check,
    disk_space_check,
    empty_password_accounts_check,
    failed_units_check,
    firewall_default_check,
    firewall_disabled_check,
    kernel_reboot_check,
    reboot_required_check,
    listener_exposure_check,
    orphaned_packages_check,
    passwordless_sudo_check,
    pending_updates_check,
    power_restore_check,
    sensitive_path_permissions_check,
    sensitive_runtime_world_writable_check,
    ssh_exposure_check,
    sshd_config_check,
    tailscale_exposure_check,
    tailscale_check,
    tailscale_ssh_check,
    uid0_accounts_check,
    world_writable_etc_check,
)


def _tailscale() -> list:
    status = collector.tailscale_status()
    if status is None:
        return []
    findings = tailscale_check(status)
    findings.extend(tailscale_ssh_check(status))
    return findings


def _ssh_exposure() -> list:
    return ssh_exposure_check(collector.ufw_rules(), collector.ufw_default_incoming())


def _power() -> list:
    return power_restore_check(collector.power_restore_state())


# Each group maps a stable prefix to the checks behind it, so `--check power`
# runs every power check and `--check sshd` runs both SSH checks. The prefix is
# the finding's namespace — the part before the dot — which is what a reader
# already sees in the report.
CHECKS: dict[str, list] = {
    "tailscale": [
        _tailscale,
        lambda: tailscale_exposure_check(collector.tailscale_services()),
    ],
    "sshd": [
        _ssh_exposure,
        lambda: sshd_config_check(collector.sshd_config()),
    ],
    "firewall": [
        lambda: firewall_disabled_check(collector.ufw_active()),
        lambda: firewall_default_check(collector.ufw_default_incoming()),
        _ssh_exposure,
    ],
    "network": [
        lambda: listener_exposure_check(
            collector.listening_ports(),
            collector.ufw_rules(),
            collector.ufw_default_incoming(),
        ),
    ],
    "security": [
        lambda: empty_password_accounts_check(collector.empty_password_accounts()),
        lambda: uid0_accounts_check(collector.uid0_accounts()),
        lambda: sensitive_path_permissions_check(collector.sensitive_path_records()),
        lambda: passwordless_sudo_check(collector.passwordless_sudo_rules()),
        lambda: sensitive_runtime_world_writable_check(*collector.sensitive_runtime_world_writable()),
    ],
    "time": [lambda: clock_check(collector.clock_state())],
    "disk": [lambda: disk_space_check(collector.disk_usage())],
    "systemd": [lambda: failed_units_check(collector.failed_units())],
    "kernel": [
        lambda: kernel_reboot_check(collector.kernel_versions()),
        lambda: reboot_required_check(collector.reboot_required_markers()),
    ],
    "packages": [
        lambda: pending_updates_check(collector.pending_update_count()),
        lambda: orphaned_packages_check(collector.orphaned_packages()),
    ],
    "config": [
        lambda: config_drift_check(collector.config_drift()),
        lambda: world_writable_etc_check(collector.world_writable_etc()),
    ],
    "power": [_power],
}


def check_prefixes() -> list:
    """Every prefix ``--check`` accepts, in report order."""
    return list(CHECKS)


def audit_with_coverage(only: str | None = None) -> tuple[list, dict]:
    """Run the checks and return ``(findings, coverage)``.

    ``coverage`` describes how complete the run was: ``readers`` counts the
    check callables attempted (fewer with ``--check``) and ``degraded`` lists
    the reader names that failed, the same names carried by the
    ``auditor.degraded`` finding's evidence.

    ``audit`` stays a plain list of findings for existing callers.
    """
    findings = []
    readers = 0

    for prefix, checks in CHECKS.items():
        if only is not None and not prefix.startswith(only):
            continue
        for check in checks:
            readers += 1
            findings.extend(check())

    errors = collector.collector_errors()
    findings.extend(auditor_degraded_check(errors))
    severity_order = {"critical": 0, "warning": 1, "info": 2}
    findings.sort(key=lambda f: severity_order[f.severity.value])
    coverage = {"readers": readers, "degraded": sorted(errors)}
    return findings, coverage


def audit(only: str | None = None) -> list:
    """Inspect the host and return every finding, worst first.

    ``only`` restricts the run to the groups whose prefix starts with it, so
    ``audit("power")`` runs the power checks and nothing else. ``None`` runs
    everything.

    A reader returning None means the thing it inspects is absent (no Tailscale
    CLI, no Mac register); that is a normal host, not an error, and the matching
    check is skipped rather than reported as broken. A reader that could not run
    at all is reported by ``auditor.degraded`` at the end.
    """
    findings, _coverage = audit_with_coverage(only)

    return findings
