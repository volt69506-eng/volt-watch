"""TDD: multiple --check prefixes in a single run (issue #102)."""

import pytest

from volt_watch import auditor, cli


def _registry(monkeypatch, calls):
    monkeypatch.setattr(
        auditor,
        "CHECKS",
        {
            name: [lambda name=name: calls.append(name) or []]
            for name in ("security", "network", "power")
        },
    )
    monkeypatch.setattr(auditor.collector, "collector_errors", lambda: {})


def test_audit_runs_every_selected_group_once(monkeypatch):
    calls = []
    _registry(monkeypatch, calls)

    auditor.audit_with_coverage(only=["security", "network"])

    assert calls == ["security", "network"]


def test_overlapping_prefixes_do_not_run_a_group_twice(monkeypatch):
    calls = []
    _registry(monkeypatch, calls)

    auditor.audit_with_coverage(only=["security", "sec"])

    assert calls == ["security"]


def test_a_single_string_still_selects_one_group(monkeypatch):
    calls = []
    _registry(monkeypatch, calls)

    auditor.audit_with_coverage(only="power")

    assert calls == ["power"]


def test_cli_accepts_repeated_check_flags(monkeypatch, capsys):
    calls = []
    _registry(monkeypatch, calls)

    assert cli.main(["--check", "security", "--check", "network"], findings=[]) == 0
    capsys.readouterr()

    # Injected findings skip the audit; the flags must still validate.
    assert cli.main(["--check", "security", "--check", "network"]) == 0
    capsys.readouterr()
    assert calls == ["security", "network"]


def test_cli_accepts_comma_separated_checks(monkeypatch, capsys):
    calls = []
    _registry(monkeypatch, calls)

    assert cli.main(["--check", "security,network"]) == 0
    capsys.readouterr()

    assert calls == ["security", "network"]


def test_cli_rejects_an_unknown_prefix_and_names_it(capsys):
    assert cli.main(["--check", "security", "--check", "bogus"], findings=[]) == 2

    assert "bogus" in capsys.readouterr().err


def test_help_documents_repeated_checks(capsys):
    with pytest.raises(SystemExit) as raised:
        cli.main(["--help"])

    assert raised.value.code == 0
    assert "--check" in capsys.readouterr().out
