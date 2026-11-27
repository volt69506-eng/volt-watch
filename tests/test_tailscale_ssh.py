"""TDD: report when Tailscale SSH is enabled (issue #77)."""

from volt_watch import auditor
from volt_watch.checks import tailscale_ssh_check
from volt_watch.severity import Severity


def _status(**self_overrides):
    self_node = {
        "HostName": "omarchy-mini",
        "DNSName": "omarchy-mini.tail.ts.net.",
        "Online": True,
        "TailscaleIPs": ["100.64.0.1"],
    }
    self_node.update(self_overrides)
    return {"Self": self_node, "BackendState": "Running"}


def test_enabled_reports_info():
    findings = tailscale_ssh_check(_status(RunSSH=True))
    assert len(findings) == 1
    f = findings[0]
    assert f.check == "tailscale.ssh_enabled"
    assert f.severity is Severity.INFO
    assert f.evidence.get("enabled") is True


def test_disabled_reports_nothing():
    assert tailscale_ssh_check(_status(RunSSH=False)) == []


def test_missing_field_reports_nothing():
    assert tailscale_ssh_check(_status()) == []


def test_unreadable_status_reports_nothing():
    assert tailscale_ssh_check(None) == []


def test_auditor_tailscale_group_runs_check(monkeypatch):
    monkeypatch.setattr(
        auditor.collector,
        "tailscale_status",
        lambda: _status(RunSSH=True),
    )
    monkeypatch.setattr(auditor.collector, "tailscale_services", lambda: [])
    checks = [f.check for f in auditor.audit(only="tailscale")]
    assert "tailscale.ssh_enabled" in checks
