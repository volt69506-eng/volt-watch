"""Tests for issue #12: running on a schedule and alerting on change.

A point-in-time auditor cannot tell "still fine" from "went bad ten minutes
ago". --output keeps the last report; --since compares against it.
"""

import json


from volt_watch import cli


def _finding(check="sshd.exposed", severity="critical", evidence=None):
    return {
        "check": check,
        "severity": severity,
        "message": f"{check} message",
        "remedy": "do the thing",
        "evidence": evidence if evidence is not None else {"port": 22},
    }


def _write(path, findings):
    path.write_text(json.dumps({"findings": findings, "counts": {}}), encoding="utf-8")
    return path


def test_output_writes_the_same_json_stdout_does(tmp_path, capsys):
    out = tmp_path / "last.json"

    code = cli.main(["--json", "--output", str(out)], findings=[_finding()])

    printed = json.loads(capsys.readouterr().out)
    written = json.loads(out.read_text(encoding="utf-8"))

    assert code == 1
    assert written == printed


def test_output_alone_does_not_change_the_exit_code(tmp_path):
    out = tmp_path / "last.json"

    assert cli.main(["--output", str(out)], findings=[]) == 0
    assert out.exists()


def test_a_new_critical_finding_exits_one(tmp_path):
    previous = _write(tmp_path / "prev.json", [])
    current = [_finding()]

    assert cli.main(["--since", str(previous)], findings=current) == 1


def test_an_unchanged_report_exits_zero(tmp_path):
    previous = _write(tmp_path / "prev.json", [_finding()])
    current = [_finding()]

    assert cli.main(["--since", str(previous)], findings=current) == 0


def test_a_resolved_finding_exits_zero(tmp_path):
    previous = _write(tmp_path / "prev.json", [_finding()])
    current = []

    assert cli.main(["--since", str(previous)], findings=current) == 0


def test_a_severity_increase_exits_one(tmp_path):
    previous = _write(tmp_path / "prev.json", [_finding(severity="warning")])
    current = [_finding(severity="critical")]

    assert cli.main(["--since", str(previous)], findings=current) == 1


def test_a_severity_decrease_exits_zero(tmp_path):
    previous = _write(tmp_path / "prev.json", [_finding(severity="critical")])
    current = [_finding(severity="warning")]

    assert cli.main(["--since", str(previous)], findings=current) == 0


def test_a_missing_since_file_says_so_and_does_not_compare(tmp_path, capsys):
    missing = tmp_path / "never-written.json"

    code = cli.main(["--json", "--since", str(missing)], findings=[])

    assert code == 0
    out = json.loads(capsys.readouterr().out)
    assert any(f["check"] == "auditor.no_baseline" for f in out["findings"])


def test_an_unreadable_since_file_does_not_crash(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("not json", encoding="utf-8")

    assert cli.main(["--since", str(bad)], findings=[]) == 0


def test_without_a_baseline_the_current_findings_still_count(tmp_path):
    """No baseline means no comparison, not a clean host."""
    missing = tmp_path / "never-written.json"

    assert cli.main(["--since", str(missing)], findings=[_finding()]) == 1


def test_output_and_since_compose(tmp_path, capsys):
    baseline = tmp_path / "baseline.json"
    cli.main(["--output", str(baseline)], findings=[_finding(severity="warning")])

    out = tmp_path / "next.json"
    code = cli.main(["--output", str(out), "--since", str(baseline)], findings=[_finding()])

    assert code == 1
    assert out.exists()


def test_the_message_text_is_not_part_of_the_identity(tmp_path):
    """A finding whose message changed is the same finding, not a new one."""
    previous = _write(tmp_path / "prev.json", [_finding()])
    changed = _finding()
    changed["message"] = "a different wording for the same problem"

    assert cli.main(["--since", str(previous)], findings=[changed]) == 0


def test_quiet_suppresses_output_but_not_the_exit_code(tmp_path, capsys):
    previous = _write(tmp_path / "prev.json", [])

    code = cli.main(["--quiet", "--since", str(previous)], findings=[_finding()])

    assert code == 1
    assert capsys.readouterr().out == ""
