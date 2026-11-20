"""Tests for issue #14: the clock is never checked.

Tailscale, TLS and log forensics all depend on the clock. A host that drifts
still passes every other check, and the first symptom is usually a confusing
auth failure days later.
"""

from volt_watch import collector
from volt_watch.checks import clock_check


class _Result:
    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.returncode = returncode


def _run(monkeypatch, mapping):
    def fake_run(cmd, **kwargs):
        key = tuple(cmd)
        for pattern, result in mapping.items():
            if key[: len(pattern)] == pattern:
                return result
        return _Result("", 0)

    monkeypatch.setattr(collector.subprocess, "run", fake_run)


def test_an_unsynchronised_clock_is_a_warning():
    findings = clock_check({"synchronised": False, "service_active": True})

    assert [f.check for f in findings] == ["time.unsynchronised"]
    assert findings[0].severity.value == "warning"


def test_a_stopped_sync_service_is_a_warning():
    findings = clock_check({"synchronised": True, "service_active": False})

    assert [f.check for f in findings] == ["time.unsynchronised"]
    assert findings[0].severity.value == "warning"


def test_a_synchronised_clock_is_clean():
    assert clock_check({"synchronised": True, "service_active": True}) == []


def test_unknown_state_is_not_a_finding():
    assert clock_check({"synchronised": None, "service_active": None}) == []


def test_reader_parses_the_state(monkeypatch):
    _run(
        monkeypatch,
        {
            ("timedatectl", "show", "-p", "NTPSynchronized", "--value"): _Result("yes\n", 0),
            ("systemctl", "is-active", "systemd-timesyncd"): _Result("active\n", 0),
        },
    )

    assert collector.clock_state() == {"synchronised": True, "service_active": True}


def test_reader_marks_a_no_answer_as_not_synchronised(monkeypatch):
    _run(monkeypatch, {("timedatectl", "show", "-p", "NTPSynchronized", "--value"): _Result("no\n", 0)})

    assert collector.clock_state()["synchronised"] is False


def test_reader_returns_empty_when_the_tool_is_absent(monkeypatch):
    def boom(cmd, **kwargs):
        raise FileNotFoundError(cmd[0])

    monkeypatch.setattr(collector.subprocess, "run", boom)

    assert collector.clock_state() == {}
