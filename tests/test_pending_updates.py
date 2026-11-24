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


def test_exit_two_means_no_updates_not_a_failure(monkeypatch):
    """pacman-contrib's checkupdates exits 2 when there are none and 0 when
    there are, the reverse of what this reader's docstring used to claim. The
    reader accepts both, but the distinction matters: exit 2 with a body would be
    a tool that changed its contract."""
    _run(monkeypatch, {("checkupdates",): _Result("", 2)})

    assert collector.pending_update_count() == 0


def test_the_checkupdates_reader_gets_a_longer_budget(monkeypatch):
    """``checkupdates`` runs ``pacman -Sy`` against the mirrors before it can
    answer, so the 5s budget every other reader gets is too tight: a slow mirror
    read as a reader that never ran, and the auditor reported a degraded audit
    on a host that was fine."""
    seen: dict = {}

    def fake_run(cmd, **kwargs):
        seen.update(kwargs)
        return _Result("", 2)

    monkeypatch.setattr(collector.subprocess, "run", fake_run)

    collector.pending_update_count()

    assert seen["timeout"] > collector.TIMEOUT_SECONDS


def test_a_checkupdates_timeout_is_still_a_degraded_reader(monkeypatch):
    """A longer budget is not no budget: a reader that never answers still has
    to be visible rather than folded into a clean report."""

    def slow(cmd, **kwargs):
        raise collector.subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 0))

    monkeypatch.setattr(collector.subprocess, "run", slow)

    assert collector.pending_update_count() is None
    # Other readers' entries may be in the map; this one has to be.
    error = collector.collector_errors()["pending_update_count"]
    assert error["kind"] == "timeout"
    assert error["reason"] == f"timed out after {collector.CHECKUPDATES_TIMEOUT_SECONDS}s"
