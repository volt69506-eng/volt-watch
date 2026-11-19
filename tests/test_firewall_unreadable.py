"""Tests for issue #9: the SSH check must not pass when the firewall could not be read.

`ufw status verbose` is a root-only wrapper on Arch/Omarchy. The collector saw a
non-zero exit and returned `[]`, which the SSH check read as "no SSH rules" and
reported nothing. That is a false negative on the auditor's headline check.
"""

import pytest

from volt_watch import collector
from volt_watch.checks import ssh_exposure_check


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


def test_ufw_rules_returns_none_when_the_command_fails(monkeypatch):
    _run(monkeypatch, {("ufw", "status", "verbose"): _Result("", 1)})

    assert collector.ufw_rules() is None


def test_ufw_rules_returns_an_empty_list_when_there_are_no_rules(monkeypatch):
    text = "Status: inactive\nDefault: deny (incoming)\n"
    _run(monkeypatch, {("ufw", "status", "verbose"): _Result(text, 0)})

    assert collector.ufw_rules() == []


def test_ufw_rules_returns_none_when_the_tool_is_missing(monkeypatch):
    def boom(cmd, **kwargs):
        raise FileNotFoundError(cmd[0])

    monkeypatch.setattr(collector.subprocess, "run", boom)

    assert collector.ufw_rules() is None


def test_default_incoming_does_not_fall_back_to_deny(monkeypatch):
    _run(monkeypatch, {("ufw", "status", "verbose"): _Result("", 1)})

    assert collector.ufw_default_incoming() is None


def test_default_incoming_reads_the_policy(monkeypatch):
    _run(monkeypatch, {("ufw", "status", "verbose"): _Result("Default: deny (incoming)\n", 0)})

    assert collector.ufw_default_incoming() == "deny"


def test_a_failed_firewall_read_is_reported_rather_than_passing(monkeypatch):
    _run(monkeypatch, {("ufw", "status", "verbose"): _Result("", 1)})

    findings = ssh_exposure_check(collector.ufw_rules(), collector.ufw_default_incoming())

    assert [f.check for f in findings] == ["sshd.firewall_unreadable"]
    assert findings[0].severity.value == "warning"


def test_a_readable_firewall_with_no_rules_reports_nothing(monkeypatch):
    _run(monkeypatch, {("ufw", "status", "verbose"): _Result("Status: inactive\n", 0)})

    findings = ssh_exposure_check(collector.ufw_rules(), "deny")

    assert findings == []
