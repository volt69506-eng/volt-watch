"""Tests for issue #7: running a single check.

Running the whole audit to iterate on one check — or to debug one false
positive on a remote host — is wasteful and noisy.
"""

import json


from volt_watch import auditor, cli


def _healthy(monkeypatch):
    monkeypatch.setattr(auditor.collector, "tailscale_status", lambda: {"BackendState": "Running"})
    monkeypatch.setattr(auditor.collector, "tailscale_services", lambda: [])
    monkeypatch.setattr(
        auditor.collector, "ufw_rules", lambda: [{"port": "22/tcp", "action": "DENY", "interface": ""}]
    )
    monkeypatch.setattr(auditor.collector, "ufw_default_incoming", lambda: "deny")
    monkeypatch.setattr(
        auditor.collector,
        "sshd_config",
        lambda: {"password_authentication": False, "permit_root_login": False},
    )
    monkeypatch.setattr(
        auditor.collector, "power_restore_state", lambda: {"present": True, "register": 0x08, "unit_enabled": True, "unit_active": True}
    )
    monkeypatch.setattr(auditor.collector, "clock_state", lambda: {"synchronised": True, "service_active": True})
    monkeypatch.setattr(auditor.collector, "pending_update_count", lambda: 0)


def test_a_single_group_runs_only_its_checks(monkeypatch):
    _healthy(monkeypatch)

    findings = auditor.audit(only="power")

    assert findings == []


def test_a_prefix_runs_every_matching_group(monkeypatch):
    """`sshd` covers both the firewall check and sshd's own configuration."""
    monkeypatch.setattr(auditor.collector, "tailscale_status", lambda: {"BackendState": "Running"})
    monkeypatch.setattr(auditor.collector, "tailscale_services", lambda: [])
    monkeypatch.setattr(auditor.collector, "ufw_rules", lambda: [{"port": "22/tcp", "action": "ALLOW", "interface": ""}])
    monkeypatch.setattr(auditor.collector, "ufw_default_incoming", lambda: "deny")
    monkeypatch.setattr(
        auditor.collector,
        "sshd_config",
        lambda: {"password_authentication": True, "permit_root_login": False},
    )
    monkeypatch.setattr(
        auditor.collector, "power_restore_state", lambda: {"present": True, "register": 0x09, "unit_enabled": True}
    )
    monkeypatch.setattr(auditor.collector, "clock_state", lambda: {"synchronised": False})
    monkeypatch.setattr(auditor.collector, "pending_update_count", lambda: 50)

    checks = [f.check for f in auditor.audit(only="sshd")]

    assert "sshd.exposed" in checks
    assert "sshd.password_auth" in checks
    # The other groups did not run.
    assert "power.restore_disabled" not in checks
    assert "time.unsynchronised" not in checks
    assert "packages.outdated" not in checks


def test_an_unknown_prefix_exits_non_zero_with_a_message(monkeypatch, capsys):
    _healthy(monkeypatch)

    code = cli.main(["--json", "--check", "nonexistent"])

    assert code == 2
    out = json.loads(capsys.readouterr().out)
    assert "nonexistent" in out["error"]
    assert "power" in out["error"]


def test_json_and_check_compose(monkeypatch, capsys):
    _healthy(monkeypatch)

    code = cli.main(["--json", "--check", "time"], findings=[])

    assert code == 0
    assert json.loads(capsys.readouterr().out)["findings"] == []


def test_the_exit_code_comes_from_the_checks_that_ran(monkeypatch):
    _healthy(monkeypatch)
    monkeypatch.setattr(
        auditor.collector, "sshd_config", lambda: {"password_authentication": True, "permit_root_login": True}
    )

    assert cli.main(["--check", "sshd"], findings=[]) == 0  # seam bypasses the audit

    findings = auditor.audit(only="sshd")
    assert any(f.severity.value == "critical" for f in findings)


def test_help_documents_the_flag():
    import subprocess

    out = subprocess.run(
        ["python3", "-m", "volt_watch.cli", "--help"],
        capture_output=True,
        text=True,
    )
    assert "--check" in out.stdout
