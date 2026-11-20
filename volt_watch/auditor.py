"""Run every check against the live host and collect the findings."""

from . import collector
from .checks import (
    auditor_degraded_check,
    clock_check,
    pending_updates_check,
    power_restore_check,
    ssh_exposure_check,
    sshd_config_check,
    tailscale_exposure_check,
    tailscale_check,
)


def _tailscale() -> list:
    status = collector.tailscale_status()
    return tailscale_check(status) if status is not None else []


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
    "time": [lambda: clock_check(collector.clock_state())],
    "packages": [lambda: pending_updates_check(collector.pending_update_count())],
    "power": [_power],
}


def check_prefixes() -> list:
    """Every prefix ``--check`` accepts, in report order."""
    return list(CHECKS)


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
    findings = []

    for prefix, checks in CHECKS.items():
        if only is not None and not prefix.startswith(only):
            continue
        for check in checks:
            findings.extend(check())

    findings.extend(auditor_degraded_check(collector.collector_errors()))

    severity_order = {"critical": 0, "warning": 1, "info": 2}
    findings.sort(key=lambda f: severity_order[f.severity.value])
    return findings
