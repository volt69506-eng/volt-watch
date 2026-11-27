"""TDD: report non-SSH listeners exposed on public interfaces."""

from volt_watch import auditor
from volt_watch.checks import listener_exposure_check
from volt_watch.severity import Severity


def test_loopback_listener_no_finding():
    listeners = [{"address": "127.0.0.1", "port": 3000, "proto": "tcp", "process": "python"}]
    assert listener_exposure_check(listeners, [], "deny") == []


def test_tailscale_listener_no_finding():
    listeners = [{"address": "100.71.164.78", "port": 55085, "proto": "tcp", "process": "tailscaled"}]
    assert listener_exposure_check(listeners, [], "deny") == []


def test_public_bind_deny_default_no_allow_rule_is_info():
    listeners = [{"address": "0.0.0.0", "port": 3000, "proto": "tcp", "process": "next"}]
    findings = listener_exposure_check(listeners, [], "deny")
    assert len(findings) == 1
    f = findings[0]
    assert f.check == "network.listener_wide_bind"
    assert f.severity is Severity.INFO


def test_public_bind_allow_default_is_warning():
    listeners = [{"address": "0.0.0.0", "port": 3000, "proto": "tcp", "process": "next"}]
    findings = listener_exposure_check(listeners, [], "allow")
    assert len(findings) == 1
    assert findings[0].severity is Severity.WARNING


def test_public_bind_with_tailscale_only_allow_no_finding():
    listeners = [{"address": "0.0.0.0", "port": 3000, "proto": "tcp", "process": "next"}]
    rules = [{"port": "3000/tcp", "action": "ALLOW", "interface": "tailscale0", "source": "Anywhere", "address": ""}]
    assert listener_exposure_check(listeners, rules, "deny") == []


def test_firewall_unreadable_returns_unknown_not_silence():
    listeners = [{"address": "0.0.0.0", "port": 3000, "proto": "tcp", "process": "next"}]
    findings = listener_exposure_check(listeners, None, "deny")
    assert len(findings) == 1
    assert findings[0].check == "network.firewall_unreadable"
    assert findings[0].severity is Severity.WARNING


def test_auditor_network_group_runs_listener_check(monkeypatch):
    monkeypatch.setattr(auditor.collector, "listening_ports", lambda: [
        {"address": "0.0.0.0", "port": 3000, "proto": "tcp", "process": "next"}
    ])
    monkeypatch.setattr(auditor.collector, "ufw_rules", lambda: [])
    monkeypatch.setattr(auditor.collector, "ufw_default_incoming", lambda: "deny")
    checks = [f.check for f in auditor.audit(only="network")]
    assert "network.listener_wide_bind" in checks
