"""TDD: report an explicitly disabled/inactive UFW firewall."""

from volt_watch import auditor
from volt_watch.checks import firewall_disabled_check
from volt_watch.severity import Severity


def test_inactive_is_critical():
    findings = firewall_disabled_check(False)

    assert len(findings) == 1
    f = findings[0]
    assert f.check == "firewall.disabled"
    assert f.severity is Severity.CRITICAL
    assert "inactive" in f.message.lower() or "disabled" in f.message.lower()
    assert "ufw enable" in f.remedy


def test_active_is_clean():
    assert firewall_disabled_check(True) == []


def test_unreadable_is_not_a_finding():
    # Unknown state is owned by sshd.firewall_unreadable / degraded readers.
    assert firewall_disabled_check(None) == []


def test_check_firewall_runs_disabled_check(monkeypatch):
    monkeypatch.setattr(auditor.collector, "ufw_rules", lambda: [])
    monkeypatch.setattr(auditor.collector, "ufw_default_incoming", lambda: "deny")
    monkeypatch.setattr(auditor.collector, "ufw_active", lambda: False)
    monkeypatch.setattr(auditor.collector, "collector_errors", dict)

    checks = [f.check for f in auditor.audit(only="firewall")]

    assert "firewall.disabled" in checks
