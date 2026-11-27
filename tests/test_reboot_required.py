"""TDD: reboot-required marker files report a finding."""

from pathlib import Path

from volt_watch import auditor
from volt_watch.checks import reboot_required_check
from volt_watch.severity import Severity


def test_marker_file_reports_warning(tmp_path):
    marker = tmp_path / "reboot-required"
    marker.write_text("kernel\n", encoding="utf-8")
    findings = reboot_required_check([str(marker)])
    assert len(findings) == 1
    f = findings[0]
    assert f.check == "system.reboot_required"
    assert f.severity is Severity.WARNING
    assert str(marker) in f.message or str(marker) in str(f.evidence)


def test_missing_marker_no_finding(tmp_path):
    assert reboot_required_check([str(tmp_path / "missing")]) == []


def test_collector_finds_known_markers(tmp_path, monkeypatch):
    from volt_watch import collector

    m1 = tmp_path / "reboot-required"
    m1.write_text("x", encoding="utf-8")
    monkeypatch.setattr(collector, "REBOOT_REQUIRED_PATHS", [str(m1), str(tmp_path / "nope")])
    assert collector.reboot_required_markers() == [str(m1)]


def test_auditor_kernel_group_runs_reboot_required(monkeypatch, tmp_path):
    marker = tmp_path / "reboot-required"
    marker.write_text("1", encoding="utf-8")
    monkeypatch.setattr(auditor.collector, "kernel_versions", lambda: {"running": "6.1.0-1", "installed": ["6.1.0-1"]})
    monkeypatch.setattr(auditor.collector, "reboot_required_markers", lambda: [str(marker)])
    checks = [f.check for f in auditor.audit(only="kernel")]
    assert "system.reboot_required" in checks
