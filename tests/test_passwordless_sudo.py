"""TDD: report passwordless sudo grants."""

from volt_watch import auditor
from volt_watch.checks import passwordless_sudo_check
from volt_watch.severity import Severity


def test_nopasswd_all_is_critical():
    rules = [{"file": "/etc/sudoers.d/99-test", "user": "yunare", "commands": "ALL", "notafter": None, "nopasswd": True}]
    findings = passwordless_sudo_check(rules)
    assert len(findings) == 1
    f = findings[0]
    assert f.check == "security.passwordless_sudo"
    assert f.severity is Severity.CRITICAL
    assert "yunare" in f.message
    assert "NOPASSWD" in f.message or "passwordless" in f.message.lower()


def test_nopasswd_narrow_command_is_warning():
    rules = [{"file": "/etc/sudoers.d/99-test", "user": "yunare", "commands": "/usr/bin/foo", "notafter": None, "nopasswd": True}]
    findings = passwordless_sudo_check(rules)
    assert findings[0].severity is Severity.WARNING


def test_expired_notafter_is_warning_even_for_all():
    rules = [{"file": "/etc/sudoers.d/99-test", "user": "yunare", "commands": "ALL", "notafter": "20200101000000Z", "nopasswd": True, "notafter_expired": True}]
    findings = passwordless_sudo_check(rules)
    assert findings[0].severity is Severity.WARNING
    assert "expired" in findings[0].message.lower() or "deadline" in findings[0].message.lower()


def test_no_nopasswd_no_finding():
    rules = [{"file": "/etc/sudoers", "user": "yunare", "commands": "ALL", "notafter": None, "nopasswd": False}]
    assert passwordless_sudo_check(rules) == []


def test_missing_sudoers_is_not_finding():
    assert passwordless_sudo_check(None) == []


def test_auditor_security_group_runs_passwordless_sudo(monkeypatch):
    monkeypatch.setattr(auditor.collector, "empty_password_accounts", lambda: [])
    monkeypatch.setattr(auditor.collector, "sensitive_path_records", lambda: [])
    monkeypatch.setattr(auditor.collector, "passwordless_sudo_rules", lambda: [
        {"file": "/etc/sudoers.d/99-test", "user": "yunare", "commands": "ALL", "notafter": None, "nopasswd": True}
    ])
    checks = [f.check for f in auditor.audit(only="security")]
    assert "security.passwordless_sudo" in checks


from volt_watch.collector import _parse_sudoers_rules, passwordless_sudo_rules


def test_collector_parses_nopasswd_all(tmp_path, monkeypatch):
    sudoers = tmp_path / "sudoers"
    sudoers.write_text("yunare ALL=(ALL) NOPASSWD: ALL\n", encoding="utf-8")
    monkeypatch.setattr("volt_watch.collector.SUDOERS_PATH", str(sudoers))
    monkeypatch.setattr("volt_watch.collector._sudoers_includes", lambda text: [])
    rules = passwordless_sudo_rules()
    assert rules[0]["user"] == "yunare"
    assert rules[0]["commands"] == "ALL"
    assert rules[0]["nopasswd"] is True


def test_collector_ignores_comment_and_non_nopasswd(tmp_path, monkeypatch):
    sudoers = tmp_path / "sudoers"
    sudoers.write_text("# yunare ALL=(ALL) NOPASSWD: ALL\nroot ALL=(ALL) ALL\n", encoding="utf-8")
    monkeypatch.setattr("volt_watch.collector.SUDOERS_PATH", str(sudoers))
    monkeypatch.setattr("volt_watch.collector._sudoers_includes", lambda text: [])
    assert passwordless_sudo_rules() == []


def test_collector_reports_expired_notafter(tmp_path, monkeypatch):
    sudoers = tmp_path / "sudoers"
    sudoers.write_text("yunare ALL=(ALL) NOTAFTER=20200101000000Z NOPASSWD: ALL\n", encoding="utf-8")
    monkeypatch.setattr("volt_watch.collector.SUDOERS_PATH", str(sudoers))
    monkeypatch.setattr("volt_watch.collector._sudoers_includes", lambda text: [])
    rules = passwordless_sudo_rules()
    assert rules[0]["notafter_expired"] is True
