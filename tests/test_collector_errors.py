"""Structured, sanitized reader failures for issue #71."""

import json
import subprocess

import pytest

from volt_watch import cli, collector


@pytest.fixture(autouse=True)
def clear_errors():
    collector.collector_errors()
    yield
    collector.collector_errors()


@pytest.mark.parametrize(
    "failure,kind,reason",
    [
        (FileNotFoundError("private detail"), "missing_tool", "not installed"),
        (
            subprocess.TimeoutExpired(
                ["tailscale", "private detail"],
                collector.TIMEOUT_SECONDS,
                output="private detail",
                stderr="private detail",
            ),
            "timeout",
            f"timed out after {collector.TIMEOUT_SECONDS}s",
        ),
        (PermissionError("private detail"), "permission", "permission denied"),
        (OSError("private detail"), "unknown", "could not run"),
        (subprocess.SubprocessError("private detail"), "unknown", "could not run"),
    ],
)
def test_reader_failures_have_stable_kinds(monkeypatch, failure, kind, reason):
    def fail(cmd, **kwargs):
        raise failure

    monkeypatch.setattr(collector.subprocess, "run", fail)

    assert collector.tailscale_status() is None
    assert collector.collector_errors() == {
        "tailscale_status": {
            "reader": "tailscale_status",
            "reason": reason,
            "kind": kind,
        }
    }
    assert collector.collector_errors() == {}


@pytest.mark.parametrize(
    "reader",
    ["tailscale_status", "tailscale_services", "sshd_config", "pending_update_count"],
)
def test_nonzero_exits_have_a_command_failed_kind(monkeypatch, reader):
    monkeypatch.setattr(
        collector.subprocess,
        "run",
        lambda cmd, **kwargs: subprocess.CompletedProcess(
            cmd, 1, stdout="private detail", stderr="private detail"
        ),
    )
    monkeypatch.setattr(collector, "_read_sshd_files", lambda: "")

    getattr(collector, reader)()

    assert collector.collector_errors() == {
        reader: {"reader": reader, "reason": "exit 1", "kind": "command_failed"}
    }


def test_network_reader_timeout_names_its_own_budget(monkeypatch):
    def fail(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])

    monkeypatch.setattr(collector.subprocess, "run", fail)

    assert collector.pending_update_count() is None
    assert collector.collector_errors() == {
        "pending_update_count": {
            "reader": "pending_update_count",
            "reason": f"timed out after {collector.CHECKUPDATES_TIMEOUT_SECONDS}s",
            "kind": "timeout",
        }
    }


def test_degraded_report_has_structured_evidence_and_readable_reasons(monkeypatch, capsys):
    def fail(cmd, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd, kwargs["timeout"], output="private detail", stderr="private detail"
        )

    monkeypatch.setattr(collector.subprocess, "run", fail)

    assert cli.main(["--check", "tailscale", "--json"]) == 1
    output = capsys.readouterr().out
    assert "private detail" not in output
    report = json.loads(output)
    finding = next(f for f in report["findings"] if f["check"] == "auditor.degraded")
    reason = f"timed out after {collector.TIMEOUT_SECONDS}s"
    readers = ["tailscale_services", "tailscale_status"]
    assert finding["evidence"]["errors"] == [
        {"reader": reader, "reason": reason, "kind": "timeout"}
        for reader in readers
    ]
    assert finding["evidence"]["readers"] == {reader: reason for reader in readers}
    assert report["coverage"]["degraded"] == readers

    assert cli.main(["--check", "tailscale"]) == 1
    output = capsys.readouterr().out
    assert "auditor.degraded" in output
    assert f"tailscale_status ({reason})" in output
    assert "private detail" not in output
