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


def audit() -> list:
    """Inspect the host and return every finding, worst first.

    A reader returning None means the thing it inspects is absent (no
    Tailscale CLI, no Mac register); that is a normal host, not an error, and
    the matching check is skipped rather than reported as broken.
    """
    findings = []

    status = collector.tailscale_status()
    if status is not None:
        findings.extend(tailscale_check(status))

    findings.extend(tailscale_exposure_check(collector.tailscale_services()))

    findings.extend(
        ssh_exposure_check(collector.ufw_rules(), collector.ufw_default_incoming())
    )

    findings.extend(sshd_config_check(collector.sshd_config()))

    findings.extend(power_restore_check(collector.power_restore_state()))

    findings.extend(clock_check(collector.clock_state()))

    findings.extend(pending_updates_check(collector.pending_update_count()))

    findings.extend(auditor_degraded_check(collector.collector_errors()))

    severity_order = {"critical": 0, "warning": 1, "info": 2}
    findings.sort(key=lambda f: severity_order[f.severity.value])
    return findings
