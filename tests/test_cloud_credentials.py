"""TDD: narrowly scoped cloud/container credential checks (issue #69).

The SSH client key part of #69 already landed in #89; this covers the other
well-known credential locations through the existing sensitive-path seam.
"""

import os

from volt_watch import collector
from volt_watch.checks import sensitive_path_permissions_check
from volt_watch.severity import Severity


def _record(path, mode, kind, expected="0600", readable=True):
    return {
        "path": path,
        "exists": True,
        "mode": mode,
        "uid": 1000,
        "gid": 1000,
        "owner": "alice",
        "group": "alice",
        "readable": readable,
        "expected": expected,
        "kind": kind,
    }


def test_collector_expands_tilde_from_the_audit_home(tmp_path, monkeypatch):
    monkeypatch.setattr(collector, "HOME", tmp_path)
    monkeypatch.setattr(collector, "SENSITIVE_PATH_SPECS", [
        {"path": "~/.aws/credentials", "kind": "cloud_credential"},
    ])
    credentials = tmp_path / ".aws" / "credentials"
    credentials.parent.mkdir()
    credentials.write_text("supersecret", encoding="utf-8")
    os.chmod(credentials, 0o600)

    records = collector.sensitive_path_records()

    assert len(records) == 1
    assert records[0]["path"] == str(credentials)
    assert records[0]["kind"] == "cloud_credential"
    assert "supersecret" not in repr(records)


def test_missing_cloud_credential_is_not_a_finding(tmp_path, monkeypatch):
    monkeypatch.setattr(collector, "HOME", tmp_path)
    monkeypatch.setattr(collector, "SENSITIVE_PATH_SPECS", [
        {"path": "~/.kube/config", "kind": "cloud_credential"},
    ])

    assert collector.sensitive_path_records() == []


def test_world_readable_aws_credentials_are_critical():
    findings = sensitive_path_permissions_check([
        _record("/home/alice/.aws/credentials", "0o644", "cloud_credential")
    ])

    assert len(findings) == 1
    assert findings[0].check == "security.sensitive_path_permissions"
    assert findings[0].severity is Severity.CRITICAL
    assert "chmod 600" in findings[0].remedy
    assert any(
        item["path"] == "/home/alice/.aws/credentials"
        for item in findings[0].evidence["paths"]
    )


def test_world_readable_docker_config_is_a_warning():
    findings = sensitive_path_permissions_check([
        _record("/home/alice/.docker/config.json", "0o644", "container_credential")
    ])

    assert len(findings) == 1
    assert findings[0].severity is Severity.WARNING


def test_safe_cloud_credential_permissions_are_clean():
    for kind in ("cloud_credential", "container_credential"):
        assert sensitive_path_permissions_check([
            _record("/home/alice/.aws/credentials", "0o600", kind)
        ]) == []


def test_unreadable_cloud_credential_reports_unknown():
    findings = sensitive_path_permissions_check([
        _record(
            "/home/alice/.config/gcloud/application_default_credentials.json",
            None, "cloud_credential", readable=False,
        )
    ])

    assert len(findings) == 1
    assert findings[0].check == "security.sensitive_path_unknown"
    assert findings[0].severity is Severity.WARNING
