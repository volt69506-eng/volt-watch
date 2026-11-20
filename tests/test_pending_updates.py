"""Tests for issue #3: pending package updates are never reported.

A host that has been offline for three months is vulnerable in a way none of the
other checks catch, and 'up to date' is the first thing a reviewer asks about.
"""

from volt_watch import collector
from volt_watch.checks import pending_updates_check


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


def test_up_to_date_is_no_finding():
    assert pending_updates_check(0) == []


def test_unknown_is_not_a_finding():
    assert pending_updates_check(None) == []


def test_a_few_updates_is_info():
    findings = pending_updates_check(5)

    assert [f.check for f in findings] == ["packages.outdated"]
    assert findings[0].severity.value == "info"


def test_a_backlog_is_a_warning():
    findings = pending_updates_check(50)

    assert findings[0].severity.value == "warning"


def test_a_host_falling_behind_is_critical():
    findings = pending_updates_check(250)

    assert findings[0].severity.value == "critical"


def test_the_threshold_boundaries():
    assert pending_updates_check(1)[0].severity.value == "info"
    assert pending_updates_check(20)[0].severity.value == "info"
    assert pending_updates_check(21)[0].severity.value == "warning"
    assert pending_updates_check(100)[0].severity.value == "warning"
    assert pending_updates_check(101)[0].severity.value == "critical"


def test_the_collector_counts_lines(monkeypatch):
    _run(
        monkeypatch,
        {("checkupdates",): _Result("pkg-a 1.0 -> 1.1\npkg-b 2.0 -> 2.1\npkg-c 3.0 -> 3.1\n", 2)},
    )

    assert collector.pending_update_count() == 3


def test_the_collector_reads_zero_updates(monkeypatch):
    _run(monkeypatch, {("checkupdates",): _Result("", 0)})

    assert collector.pending_update_count() == 0


def test_exit_two_is_updates_available_not_a_failure(monkeypatch):
    """checkupdates exits 2 when there ARE updates; treating that as a failure
    would make the check silent exactly when it has something to say."""
    _run(monkeypatch, {("checkupdates",): _Result("pkg 1.0 -> 1.1\n", 2)})

    assert collector.pending_update_count() == 1


def test_the_collector_returns_none_when_the_tool_is_absent(monkeypatch):
    def boom(cmd, **kwargs):
        raise FileNotFoundError(cmd[0])

    monkeypatch.setattr(collector.subprocess, "run", boom)

    assert collector.pending_update_count() is None


def test_the_collector_returns_none_when_the_command_fails(monkeypatch):
    _run(monkeypatch, {("checkupdates",): _Result("", 1)})

    assert collector.pending_update_count() is None
