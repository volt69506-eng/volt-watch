"""Run every check against the live host and collect the findings."""

from . import collector
from .checks import (
    power_restore_check,
    ssh_exposure_check,
    sshd_config_check,
    tailscale_exposure_check,
    tailscale_check,
)
from .finding import Finding
from .severity import Severity


def audit() -> list:
    """Inspect the host and return findings, including incomplete reads, worst first."""
    collector.reset_collector_errors()
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

    if failures := collector.collector_errors():
        summary = ", ".join(f"{reader}: {reason}" for reader, reason in sorted(failures.items()))
        findings.append(
            Finding(
                "auditor.degraded",
                Severity.WARNING,
                f"Some host checks could not be completed ({summary}).",
                "Check that the required tools are installed and readable by the auditor.",
                {"failed_readers": failures},
            )
        )

    severity_order = {"critical": 0, "warning": 1, "info": 2}
    findings.sort(key=lambda f: severity_order[f.severity.value])
    return findings
