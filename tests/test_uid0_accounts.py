"""TDD: a second UID 0 account is a finding (issue #87)."""

from volt_watch import auditor, collector
from volt_watch.checks import uid0_accounts_check
from volt_watch.severity import Severity


PASSWD = """\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
toor:x:0:0::/home/toor:/bin/bash
sync:x:4:65534:sync:/bin:/bin/sync
broken-line
"""


def test_collector_returns_only_uid_zero_accounts(tmp_path):
    passwd = tmp_path / "passwd"
    passwd.write_text(PASSWD, encoding="utf-8")

    assert collector.uid0_accounts(str(passwd)) == [
        {"name": "root", "uid": 0, "home": "/root", "shell": "/bin/bash"},
        {"name": "toor", "uid": 0, "home": "/home/toor", "shell": "/bin/bash"},
    ]


def test_collector_never_returns_the_password_field(tmp_path):
    passwd = tmp_path / "passwd"
    passwd.write_text("toor:$6$salt$hash:0:0::/home/toor:/bin/bash\n", encoding="utf-8")

    assert "$" not in repr(collector.uid0_accounts(str(passwd)))


def test_missing_passwd_is_a_clean_answer(tmp_path):
    assert collector.uid0_accounts(str(tmp_path / "absent")) == []


def test_unreadable_passwd_is_unknown(tmp_path, monkeypatch):
    passwd = tmp_path / "passwd"
    passwd.write_text("root:x:0:0:root:/root:/bin/bash\n", encoding="utf-8")

    def denied(self, *args, **kwargs):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr("pathlib.Path.read_text", denied)

    assert collector.uid0_accounts(str(passwd)) is None


def test_unreadable_passwd_reports_unknown_not_clean():
    findings = uid0_accounts_check(None)

    assert len(findings) == 1
    assert findings[0].check == "security.passwd_unreadable"
    assert findings[0].severity is Severity.WARNING


def test_only_root_is_allowed_as_uid_zero():
    assert uid0_accounts_check([
        {"name": "root", "uid": 0, "home": "/root", "shell": "/bin/bash"}
    ]) == []


def test_each_extra_uid_zero_account_is_critical():
    findings = uid0_accounts_check([
        {"name": "root", "uid": 0, "home": "/root", "shell": "/bin/bash"},
        {"name": "toor", "uid": 0, "home": "/home/toor", "shell": "/bin/bash"},
        {"name": "admin2", "uid": 0, "home": "/home/admin2", "shell": "/bin/zsh"},
    ])

    assert [f.check for f in findings] == ["security.uid0_account"] * 2
    assert all(f.severity is Severity.CRITICAL for f in findings)
    assert [f.evidence["name"] for f in findings] == ["toor", "admin2"]
    assert all("$" not in repr(f.as_dict()) for f in findings)


def test_the_security_group_runs_the_check(monkeypatch):
    monkeypatch.setattr(collector, "uid0_accounts", lambda: [
        {"name": "toor", "uid": 0, "home": "/home/toor", "shell": "/bin/bash"}
    ])
    monkeypatch.setattr(collector, "empty_password_accounts", lambda: [])
    monkeypatch.setattr(collector, "sensitive_path_records", lambda: [])
    monkeypatch.setattr(collector, "passwordless_sudo_rules", lambda: [])
    monkeypatch.setattr(collector, "sensitive_runtime_world_writable", lambda: ([], []))

    checks = [f.check for f in auditor.audit(only="security")]

    assert "security.uid0_account" in checks
