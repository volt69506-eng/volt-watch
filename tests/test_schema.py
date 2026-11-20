"""Tests for issue #13: the JSON report has no schema version.

A consumer parsing the report cannot tell which version produced it, and a
finding added later looks identical to one that has always been there.
"""

import json
import platform

from volt_watch import cli


def _finding():
    return {
        "check": "sshd.exposed",
        "severity": "critical",
        "message": "SSH is open",
        "remedy": "Restrict it",
        "evidence": {"port": 22},
    }


def test_the_payload_carries_a_version(capsys):
    cli.main(["--json"], findings=[_finding()])

    out = json.loads(capsys.readouterr().out)

    assert out["version"] == 1
    assert isinstance(out["version"], int)


def test_the_payload_names_the_host(capsys):
    cli.main(["--json"], findings=[])

    out = json.loads(capsys.readouterr().out)

    assert out["host"] == platform.node()


def test_findings_is_still_a_list(capsys):
    cli.main(["--json"], findings=[_finding()])

    out = json.loads(capsys.readouterr().out)

    assert isinstance(out["findings"], list)
    assert out["findings"][0]["check"] == "sshd.exposed"


def test_the_wrapper_does_not_disturb_the_counts(capsys):
    cli.main(["--json"], findings=[_finding()])

    out = json.loads(capsys.readouterr().out)

    assert out["counts"]["critical"] == 1
    assert out["counts"]["total"] == 1


def test_output_writes_the_same_wrapper(tmp_path, capsys):
    out_file = tmp_path / "last.json"

    cli.main(["--json", "--output", str(out_file)], findings=[_finding()])

    printed = json.loads(capsys.readouterr().out)
    written = json.loads(out_file.read_text(encoding="utf-8"))

    assert written == printed
    assert written["version"] == 1


def test_the_plain_output_is_unchanged(capsys):
    cli.main([], findings=[_finding()])

    out = capsys.readouterr().out

    assert "critical  sshd.exposed" in out
    assert "1 finding(s)" in out
    assert "version" not in out
