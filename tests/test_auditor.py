"""Tests for the auditor that ties readers to checks."""

import json
import subprocess

from volt_watch import auditor, collector
from volt_watch.cli import main


def _collector(monkeypatch, **values):
    """Replace collector readers with functions returning the given values.

    Each value is a zero-argument lambda supplying the reader's result; the
    replacement calls it so the reader returns the payload, not the lambda.
    """
    values.setdefault("tailscale_services", lambda: [])
    values.setdefault("sshd_config", lambda: {"password_authentication": False, "permit_root_login": False})
    for name, produce in values.items():
        monkeypatch.setattr(auditor.collector, name, lambda *, _produce=produce: _produce())


def test_audit_reports_nothing_on_a_healthy_host(monkeypatch):
    _collector(
        monkeypatch,
        tailscale_status=lambda: {"BackendState": "Running", "Self": {}},
        ufw_rules=lambda: [
            {"port": "22/tcp", "action": "ALLOW", "interface": "tailscale0"},
            {"port": "22/tcp", "action": "DENY", "interface": ""},
        ],
        ufw_default_incoming=lambda: "deny",
        power_restore_state=lambda: {"present": True, "register": 0x08, "unit_enabled": True},
    )

    assert auditor.audit() == []


def test_audit_collects_findings_from_every_check(monkeypatch):
    _collector(
        monkeypatch,
        tailscale_status=lambda: {"BackendState": "NeedsLogin", "Self": {}},
        ufw_rules=lambda: [{"port": "22/tcp", "action": "ALLOW", "interface": ""}],
        ufw_default_incoming=lambda: "deny",
        power_restore_state=lambda: {"present": True, "register": 0x09, "unit_enabled": False},
    )

    checks = [f.check for f in auditor.audit()]

    assert "tailscale.backend" in checks
    assert "sshd.exposed" in checks
    assert "power.restore_disabled" in checks
    assert "power.unit_disabled" in checks


def test_audit_skips_tailscale_when_the_cli_is_absent(monkeypatch):
    _collector(
        monkeypatch,
        tailscale_status=lambda: None,
        ufw_rules=lambda: [],
        ufw_default_incoming=lambda: "deny",
        power_restore_state=lambda: {"present": False, "register": None, "unit_enabled": None},
    )

    checks = [f.check for f in auditor.audit()]

    assert "tailscale.backend" not in checks


def test_audit_reports_a_missing_power_register(monkeypatch):
    _collector(
        monkeypatch,
        tailscale_status=lambda: {"BackendState": "Running", "Self": {}},
        ufw_rules=lambda: [],
        ufw_default_incoming=lambda: "deny",
        power_restore_state=lambda: {"present": False, "register": None, "unit_enabled": None},
    )

    checks = [f.check for f in auditor.audit()]

    assert "power.register_missing" in checks


def test_cli_reports_unavailable_readers_in_json_and_quiet_mode(monkeypatch, capsys):
    def missing(cmd, **_kwargs):
        raise FileNotFoundError(cmd[0])

    monkeypatch.setattr(collector.subprocess, "run", missing)
    monkeypatch.setattr(collector, "_read_sshd_files", lambda: "")

    assert main(["--json"]) == 1
    findings = json.loads(capsys.readouterr().out)["findings"]
    degraded = [finding for finding in findings if finding["check"] == "auditor.degraded"]
    assert len(degraded) == 1
    assert degraded[0]["severity"] == "warning"
    assert degraded[0]["evidence"]["failed_readers"] == {
        "tailscale_status": "not installed",
        "tailscale_services": "not installed",
        "ufw_rules": "not installed",
        "ufw_default_incoming": "not installed",
        "sshd_config": "not installed",
        "power_restore_state": "not installed",
    }

    assert main(["--quiet"]) == 1
    assert not capsys.readouterr().out


def test_audit_reports_timeout_and_exit_then_clears_them_on_success(monkeypatch, capsys):
    status = ("tailscale", "status", "--json")
    services = ("tailscale", "serve", "status", "--json")
    responses = {
        status: json.dumps({"BackendState": "Running", "Self": {}}),
        services: "{}",
        ("ufw", "status", "verbose"): "Status: active\nDefault: deny (incoming)\n",
        ("setpci", "-s", "00:1f.0", "0xa4.b"): "08\n",
        ("systemctl", "is-enabled", collector.POWER_UNIT): "enabled\n",
    }
    failures = {status: subprocess.TimeoutExpired(status, 30), services: 7, ("sshd", "-T"): 1}

    def run(cmd, **_kwargs):
        key = tuple(cmd)
        failure = failures.get(key)
        if isinstance(failure, subprocess.TimeoutExpired):
            raise failure
        if failure is not None:
            return subprocess.CompletedProcess(cmd, failure, stdout="", stderr="diagnostic")
        return subprocess.CompletedProcess(cmd, 0, stdout=responses[key], stderr="")

    monkeypatch.setattr(collector.subprocess, "run", run)
    monkeypatch.setattr(collector, "_read_sshd_files", lambda: "PasswordAuthentication no\nPermitRootLogin no\n")

    (degraded,) = auditor.audit()
    assert degraded.check == "auditor.degraded"
    assert degraded.evidence["failed_readers"] == {"tailscale_status": "timed out", "tailscale_services": "exit 7"}
    assert collector.collector_errors() == degraded.evidence["failed_readers"]
    assert main(["--quiet"]) == 1
    assert not capsys.readouterr().out

    del failures[status]
    del failures[services]
    assert auditor.audit() == []
    assert collector.collector_errors() == {}
