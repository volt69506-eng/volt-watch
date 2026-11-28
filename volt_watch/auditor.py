"""Run every check against the live host and collect the findings."""

import ast
from pathlib import Path

from . import collector
from .checks import (
    auditor_degraded_check,
    boot_preset_check,
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
        lambda: boot_preset_check(collector.boot_flow()),
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


def _ast_finding_registry() -> tuple[dict[str, set[str]], dict[str, set[str]], dict[str, list[str]]]:
    direct: dict[str, set[str]] = {}
    calls: dict[str, set[str]] = {}
    group_refs: dict[str, list[str]] = {}

    for name in ("checks.py", "auditor.py"):
        tree = ast.parse(Path(__file__).with_name(name).read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.FunctionDef):
                fn_findings: set[str] = set()
                fn_calls: set[str] = set()
                for child in ast.walk(node):
                    if isinstance(child, ast.Call) and isinstance(child.func, ast.Name):
                        fn_calls.add(child.func.id)
                        if child.func.id == "Finding":
                            for kw in child.keywords:
                                if kw.arg == "check" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                                    fn_findings.add(kw.value.value)
                direct[node.name] = fn_findings
                calls[node.name] = fn_calls
            if name == "auditor.py" and isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if any(isinstance(t, ast.Name) and t.id == "CHECKS" for t in targets) and isinstance(node.value, ast.Dict):
                    for key, val in zip(node.value.keys, node.value.values):
                        if isinstance(key, ast.Constant) and isinstance(key.value, str) and isinstance(val, ast.List):
                            refs: list[str] = []
                            for elt in val.elts:
                                if isinstance(elt, ast.Name):
                                    refs.append(elt.id)
                                else:
                                    for sub in ast.walk(elt):
                                        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
                                            refs.append(sub.func.id)
                            group_refs[key.value] = refs
    return direct, calls, group_refs


def list_checks() -> list[dict]:
    """Return sorted registered check groups, prefixes, and finding names without host reads."""
    direct, calls, group_refs = _ast_finding_registry()

    def resolve(fn_name: str, seen: set[str]) -> set[str]:
        if fn_name in seen:
            return set()
        seen.add(fn_name)
        found = set(direct.get(fn_name, ()))
        for callee in calls.get(fn_name, ()):
            found.update(resolve(callee, seen))
        return found

    out = []
    for group in sorted(check_prefixes()):
        findings: set[str] = set()
        for ref in group_refs.get(group, ()):
            findings.update(resolve(ref, set()))
        ordered = sorted(findings)
        out.append({
            "group": group,
            "prefixes": sorted({name.split(".", 1)[0] for name in ordered}),
            "findings": ordered,
        })
    return out


def audit_with_coverage(only: str | list[str] | None = None) -> tuple[list, dict]:
    """Run the checks and return ``(findings, coverage)``.

    ``only`` keeps its original single-string form and also accepts a list of
    prefixes: a group runs when any prefix matches it. Groups are still
    iterated once, so overlapping prefixes cannot duplicate findings.

    ``coverage`` describes how complete the run was: ``readers`` counts the
    check callables attempted (fewer with ``--check``) and ``degraded`` lists
    the reader names that failed, the same names carried by the
    ``auditor.degraded`` finding's evidence.

    ``audit`` stays a plain list of findings for existing callers.
    """
    selected = None if only is None else ([only] if isinstance(only, str) else list(only))
    findings = []
    readers = 0

    for prefix, checks in CHECKS.items():
        if selected is not None and not any(prefix.startswith(s) for s in selected):
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


def audit(only: str | list[str] | None = None) -> list:
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
