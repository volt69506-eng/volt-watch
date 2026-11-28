"""TDD: --format json/ndjson output for automation (issue #70)."""

import json

import pytest

from volt_watch import cli


def _finding(check="x", severity="warning"):
    return {
        "check": check,
        "severity": severity,
        "message": f"{check} message",
        "remedy": "fix it",
        "evidence": {"key": "value"},
    }


def test_format_json_matches_the_json_flag(capsys):
    assert cli.main(["--json"], findings=[_finding()]) == 0
    legacy = json.loads(capsys.readouterr().out)

    assert cli.main(["--format", "json"], findings=[_finding()]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["version"] == legacy["version"]
    assert payload["findings"] == legacy["findings"]
    assert payload["coverage"] == legacy["coverage"]
    assert payload["counts"] == legacy["counts"]


def test_default_output_stays_human_readable(capsys):
    assert cli.main([], findings=[_finding()]) == 1

    assert "1 finding(s)" in capsys.readouterr().out


def test_ndjson_starts_with_meta_then_one_line_per_finding(capsys):
    assert cli.main(["--format", "ndjson"], findings=[_finding("a"), _finding("b", "critical")]) == 1

    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 3
    meta = json.loads(lines[0])
    assert meta["record"] == "meta"
    assert meta["version"] == 2
    assert "coverage" in meta and "counts" in meta and "generated_at" in meta
    assert [json.loads(line)["check"] for line in lines[1:]] == ["a", "b"]
    assert all("\x1b[" not in line for line in lines)


def test_ndjson_with_no_findings_has_only_the_meta_line(capsys):
    assert cli.main(["--format", "ndjson"], findings=[]) == 0

    lines = capsys.readouterr().out.splitlines()
    assert json.loads(lines[0])["counts"]["total"] == 0
    assert len(lines) == 1


def test_ndjson_meta_carries_degraded_coverage(capsys):
    degraded = _finding("auditor.degraded", "warning")
    degraded["evidence"] = {"readers": {"sshd": "missing tool"}}

    assert cli.main(["--format", "ndjson"], findings=[degraded]) == 1

    meta = json.loads(capsys.readouterr().out.splitlines()[0])
    assert meta["coverage"]["degraded"] == ["sshd"]


def test_format_ndjson_still_writes_a_json_baseline(tmp_path, capsys):
    out = tmp_path / "last.json"

    assert cli.main(["--format", "ndjson", "--output", str(out)], findings=[_finding()]) == 1
    capsys.readouterr()

    baseline = json.loads(out.read_text(encoding="utf-8"))
    assert baseline["version"] == 2
    assert baseline["findings"][0]["check"] == "x"


def test_invalid_format_is_a_usage_error(capsys):
    assert cli.main(["--format", "xml"], findings=[_finding()]) == 2

    assert "--format" in capsys.readouterr().err


def test_format_json_has_no_ansi_escapes(capsys):
    assert cli.main(["--format", "json"], findings=[_finding()]) == 1

    assert "\x1b[" not in capsys.readouterr().out


def test_help_documents_format(capsys):
    with pytest.raises(SystemExit) as raised:
        cli.main(["--help"])

    assert raised.value.code == 0
    assert "--format" in capsys.readouterr().out
