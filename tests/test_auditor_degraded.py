"""Tests for issue #11: the auditor must not report clean when it could not read.

A safety tool whose inputs all failed and that still prints "no findings" is
worse than one that crashes: the silence reads as a clean bill of health.
"""

import json
import subprocess

from volt_watch import cli, collector


class _Result:
    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.returncode = returncode


def _no_tools(monkeypatch):
    """Route every command to a missing tool."""

    def boom(cmd, **kwargs):
        raise FileNotFoundError(cmd[0])

    monkeypatch.setattr(collector.subprocess, "run", boom)
    collector.collector_errors()


def test_a_host_with_no_tools_reports_degraded(monkeypatch):
    _no_tools(monkeypatch)

    findings = cli.audit()

    assert any(f.check == "auditor.degraded" for f in findings)


def test_a_degraded_audit_exits_one(monkeypatch, capsys):
    _no_tools(monkeypatch)

    code = cli.main(["--json"])

    assert code == 1
    out = json.loads(capsys.readouterr().out)
    degraded = [f for f in out["findings"] if f["check"] == "auditor.degraded"]
    assert degraded, out


def test_the_json_names_the_failed_readers(monkeypatch, capsys):
    _no_tools(monkeypatch)

    cli.main(["--json"])
    out = json.loads(capsys.readouterr().out)

    degraded = [f for f in out["findings"] if f["check"] == "auditor.degraded"][0]
    assert degraded["evidence"]["readers"]
    assert "not installed" in next(iter(degraded["evidence"]["readers"].values()))


def test_quiet_still_exits_one(monkeypatch, capsys):
    _no_tools(monkeypatch)

    code = cli.main(["--quiet"])

    assert code == 1
    assert capsys.readouterr().out == ""


def test_a_reader_that_answers_is_not_listed(monkeypatch):
    monkeypatch.setattr(
        collector, "tailscale_status", lambda: {"BackendState": "Running"}
    )
    monkeypatch.setattr(collector, "tailscale_services", lambda: [])
    monkeypatch.setattr(collector, "ufw_rules", lambda: [])
    monkeypatch.setattr(collector, "ufw_default_incoming", lambda: "deny")
    monkeypatch.setattr(
        collector, "sshd_config", lambda: {"password_authentication": False, "permit_root_login": False}
    )
    monkeypatch.setattr(
        collector, "power_restore_state", lambda: {"present": False, "register": None}
    )
    collector.collector_errors()

    assert collector.collector_errors() == {}


def test_a_nonzero_exit_is_recorded(monkeypatch):
    def fake_run(cmd, **kwargs):
        return _Result("", 1)

    monkeypatch.setattr(collector.subprocess, "run", fake_run)
    collector.tailscale_status()

    errors = collector.collector_errors()

    assert errors == {
        "tailscale_status": {
            "reader": "tailscale_status", "reason": "exit 1", "kind": "command_failed"
        }
    }


def test_a_timeout_is_recorded_as_such(monkeypatch):
    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, collector.TIMEOUT_SECONDS)

    monkeypatch.setattr(collector.subprocess, "run", fake_run)
    collector.tailscale_status()

    errors = collector.collector_errors()

    assert errors == {
        "tailscale_status": {
            "reader": "tailscale_status",
            "reason": f"timed out after {collector.TIMEOUT_SECONDS}s",
            "kind": "timeout",
        }
    }


def test_the_timeout_is_a_named_constant():
    """A magic number at the call site cannot be argued about or changed."""
    assert isinstance(collector.TIMEOUT_SECONDS, int)
    assert 0 < collector.TIMEOUT_SECONDS <= 15


def test_the_run_helper_passes_the_configured_timeout(monkeypatch):
    seen = {}

    def fake_run(cmd, **kwargs):
        seen.update(kwargs)
        return _Result("", 0)

    monkeypatch.setattr(collector.subprocess, "run", fake_run)
    collector.tailscale_status()

    assert seen["timeout"] == collector.TIMEOUT_SECONDS


def test_a_timed_out_reader_returns_the_absent_sentinel(monkeypatch):
    """A hung tool must not look like a healthy answer."""

    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, collector.TIMEOUT_SECONDS)

    monkeypatch.setattr(collector.subprocess, "run", fake_run)

    assert collector.tailscale_status() is None
    assert collector.collector_errors() == {
        "tailscale_status": {
            "reader": "tailscale_status",
            "reason": f"timed out after {collector.TIMEOUT_SECONDS}s",
            "kind": "timeout",
        }
    }
