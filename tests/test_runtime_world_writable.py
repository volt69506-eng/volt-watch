"""TDD: detect world-writable files in sensitive runtime dirs (#79)."""

import os
import stat
from pathlib import Path

from volt_watch import auditor
from volt_watch.checks import sensitive_runtime_world_writable_check
from volt_watch.severity import Severity


def test_world_writable_file_reported(tmp_path):
    d = tmp_path / "tailscale"
    d.mkdir()
    f = d / "state"
    f.write_text("x", encoding="utf-8")
    os.chmod(f, 0o666)
    from volt_watch.collector import sensitive_runtime_world_writable
    records, errors = sensitive_runtime_world_writable([str(d)])
    findings = sensitive_runtime_world_writable_check(records, errors)
    checks = [x.check for x in findings]
    assert "security.world_writable_sensitive_runtime" in checks
    finding = [x for x in findings if x.check == "security.world_writable_sensitive_runtime"][0]
    assert finding.severity is Severity.CRITICAL
    assert str(f) in str(finding.evidence)


def test_missing_dir_no_finding(tmp_path):
    from volt_watch.collector import sensitive_runtime_world_writable
    records, errors = sensitive_runtime_world_writable([str(tmp_path / "missing")])
    assert sensitive_runtime_world_writable_check(records, errors) == []


def test_unreadable_dir_reports_unknown(tmp_path, monkeypatch):
    d = tmp_path / "tailscale"
    d.mkdir()
    real_scandir = os.scandir

    def fake_scandir(path):
        if str(path) == str(d):
            raise PermissionError("denied")
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", fake_scandir)
    from volt_watch.collector import sensitive_runtime_world_writable
    records, errors = sensitive_runtime_world_writable([str(d)])
    findings = sensitive_runtime_world_writable_check(records, errors)
    assert [f.check for f in findings] == ["security.sensitive_runtime_unknown"]
    assert findings[0].severity is Severity.WARNING


def test_auditor_security_group_runs_check(monkeypatch, tmp_path):
    d = tmp_path / "tailscale"
    d.mkdir()
    f = d / "state"
    f.write_text("x", encoding="utf-8")
    os.chmod(f, 0o666)
    monkeypatch.setattr(auditor.collector, "empty_password_accounts", lambda: [])
    monkeypatch.setattr(auditor.collector, "sensitive_path_records", lambda: [])
    monkeypatch.setattr(auditor.collector, "passwordless_sudo_rules", lambda: [])
    monkeypatch.setattr(auditor.collector, "sensitive_runtime_world_writable", lambda: ([{"path": str(f), "mode": "0o666", "is_dir": False}], []))
    checks = [f.check for f in auditor.audit(only="security")]
    assert "security.world_writable_sensitive_runtime" in checks
