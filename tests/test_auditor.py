"""Tests for the auditor that ties readers to checks."""

from volt_watch import auditor


#: Readers added after these tests were written. They default to "answered,
#: nothing to report" so a test that only cares about one check does not have to
#: spell out every reader the audit now calls.
_READER_DEFAULTS = {
    "tailscale_services": list,
    "sshd_config": lambda: None,
}


def _collector(monkeypatch, **values):
    """Replace collector readers with functions returning the given values.

    Each value is a zero-argument lambda supplying the reader's result; the
    replacement calls it so the reader returns the payload, not the lambda.
    """
    for name, produce in {**_READER_DEFAULTS, **values}.items():
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
