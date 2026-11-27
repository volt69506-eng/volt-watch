"""TDD: --fail-on sets the severity threshold for the exit code (issue #86)."""

import json

import pytest

from volt_watch import cli


def _finding(check="x", severity="warning", evidence=None):
    return {
        "check": check,
        "severity": severity,
        "message": f"{check} message",
        "remedy": "",
        "evidence": evidence if evidence is not None else {},
    }


def _baseline(path, findings):
    path.write_text(json.dumps({"findings": findings, "counts": {}}), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    "threshold,severity,expected",
    [
        ("critical", "warning", 0),
        ("critical", "critical", 1),
        ("warning", "info", 0),
        ("warning", "warning", 1),
        ("info", "info", 1),
    ],
)
def test_fail_on_threshold_decides_the_exit_code(threshold, severity, expected):
    assert cli.main(["--fail-on", threshold], findings=[_finding(severity=severity)]) == expected


def test_default_threshold_still_ignores_info(capsys):
    assert cli.main([], findings=[_finding(severity="info")]) == 0
    capsys.readouterr()


def test_an_invalid_threshold_is_a_usage_error(capsys):
    assert cli.main(["--fail-on", "catastrophic"], findings=[_finding()]) == 2

    assert "--fail-on" in capsys.readouterr().err


def test_degraded_audit_always_fails_even_below_the_threshold(capsys):
    findings = [_finding("auditor.degraded", "warning")]

    assert cli.main(["--fail-on", "critical"], findings=findings) == 1
    capsys.readouterr()


def test_since_applies_the_threshold_to_new_findings(tmp_path, capsys):
    previous = _baseline(tmp_path / "prev.json", [])

    assert cli.main(
        ["--since", str(previous), "--fail-on", "critical"],
        findings=[_finding("new.warning", "warning")],
    ) == 0
    capsys.readouterr()
    assert cli.main(
        ["--since", str(previous), "--fail-on", "critical"],
        findings=[_finding("new.critical", "critical")],
    ) == 1
    capsys.readouterr()


def test_since_without_a_threshold_keeps_alerting_on_any_new_finding(tmp_path, capsys):
    previous = _baseline(tmp_path / "prev.json", [])

    assert cli.main(["--since", str(previous)], findings=[_finding(severity="info")]) == 1
    capsys.readouterr()


def test_help_documents_fail_on(capsys):
    with pytest.raises(SystemExit) as raised:
        cli.main(["--help"])

    assert raised.value.code == 0
    assert "--fail-on" in capsys.readouterr().out


def test_fail_on_does_not_change_the_report(capsys):
    payload = cli.main(["--json", "--fail-on", "critical"], findings=[_finding("a", "warning")])

    assert payload == 0
    report = json.loads(capsys.readouterr().out)
    assert [f["check"] for f in report["findings"]] == ["a"]
