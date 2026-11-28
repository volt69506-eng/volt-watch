"""TDD: --list-checks discovers check groups, prefixes, and finding names without host reads."""

import json

from volt_watch import auditor, cli


def test_list_checks_text_output_is_sorted_and_complete(capsys):
    code = cli.main(["--list-checks"])
    assert code == 0
    out = capsys.readouterr().out
    assert "security (prefixes: security)" in out
    assert "kernel (prefixes: boot, kernel, system)" in out
    assert "  - security.sensitive_path_permissions" in out
    assert "  - power.unit_failed" in out

    # Group headers appear in sorted order for diffable text output.
    headers = [line.split(" ", 1)[0] for line in out.splitlines() if line and not line.startswith("  ")]
    assert headers == sorted(auditor.check_prefixes())


def test_list_checks_json_and_ndjson_shape(capsys):
    code = cli.main(["--list-checks", "--format", "json"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["version"] == cli.REPORT_VERSION
    assert isinstance(payload["checks"], list)
    by_group = {entry["group"]: entry for entry in payload["checks"]}
    assert set(by_group) == set(auditor.check_prefixes())
    assert by_group["kernel"]["prefixes"] == ["boot", "kernel", "system"]
    assert "kernel.pending_reboot" in by_group["kernel"]["findings"]

    code = cli.main(["--list-checks", "--format", "ndjson"])
    assert code == 0
    ndjson_lines = capsys.readouterr().out.strip().splitlines()
    assert len(ndjson_lines) == 1
    assert json.loads(ndjson_lines[0]) == payload


def test_list_checks_performs_no_host_reads(monkeypatch, capsys):
    def fail_audit(*args, **kwargs):
        raise AssertionError("audit_with_coverage must not run for --list-checks")

    monkeypatch.setattr(cli, "audit_with_coverage", fail_audit)
    assert cli.main(["--list-checks"]) == 0
    assert "power" in capsys.readouterr().out


def test_list_checks_rejects_since_and_output(capsys):
    assert cli.main(["--list-checks", "--since", "prev.json"]) == 2
    assert cli.main(["--list-checks", "--output", "out.json"]) == 2
    capsys.readouterr()
