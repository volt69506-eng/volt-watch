"""TDD: sensitive local secret/state file permissions are audited."""

import os
import stat

from volt_watch import auditor
from volt_watch.checks import sensitive_path_permissions_check
from volt_watch.severity import Severity


def _write(path, mode, uid=0, gid=0):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"secret")
    os.chmod(path, mode)
    os.chown(path, uid, gid)
    return path


def test_missing_path_is_not_a_finding(tmp_path, monkeypatch):
    monkeypatch.setattr(auditor.collector, "sensitive_path_records", lambda: [])
    assert sensitive_path_permissions_check([]) == []


def test_world_readable_luks_keyfile_is_critical(tmp_path):
    rec = {
        "path": "/crypto_keyfile.bin",
        "exists": True,
        "mode": "0o644",
        "uid": 0,
        "gid": 0,
        "owner": "root",
        "group": "root",
        "readable": True,
        "expected": "0400 root-owned",
    }
    findings = sensitive_path_permissions_check([rec])
    assert len(findings) == 1
    f = findings[0]
    assert f.check == "security.sensitive_path_permissions"
    assert f.severity is Severity.CRITICAL
    assert "/crypto_keyfile.bin" in f.message
    assert "chmod" in f.remedy or "0400" in f.remedy
    assert f.evidence["paths"][0]["path"] == "/crypto_keyfile.bin"
    assert "secret" not in str(f.evidence).lower()


def test_world_readable_docker_sock_is_critical():
    rec = {
        "path": "/run/docker.sock",
        "exists": True,
        "mode": "0o666",
        "uid": 0,
        "gid": 0,
        "owner": "root",
        "group": "root",
        "readable": True,
        "expected": "root:docker 0660 or stricter",
    }
    findings = sensitive_path_permissions_check([rec])
    assert findings[0].severity is Severity.CRITICAL


def test_ssh_host_private_key_too_permissive_is_critical():
    rec = {
        "path": "/etc/ssh/ssh_host_ed25519_key",
        "exists": True,
        "mode": "0o644",
        "uid": 0,
        "gid": 0,
        "owner": "root",
        "group": "root",
        "readable": True,
        "expected": "0600 root-owned",
    }
    findings = sensitive_path_permissions_check([rec])
    assert findings[0].severity is Severity.CRITICAL


def test_tailscale_state_world_readable_is_warning_or_critical():
    rec = {
        "path": "/var/lib/tailscale/tailscaled.state",
        "exists": True,
        "mode": "0o644",
        "uid": 0,
        "gid": 0,
        "owner": "root",
        "group": "root",
        "readable": True,
        "expected": "not world-readable",
    }
    findings = sensitive_path_permissions_check([rec])
    assert len(findings) == 1
    assert findings[0].severity in (Severity.WARNING, Severity.CRITICAL)


def test_safe_permissions_no_finding():
    rec = {
        "path": "/crypto_keyfile.bin",
        "exists": True,
        "mode": "0o400",
        "uid": 0,
        "gid": 0,
        "owner": "root",
        "group": "root",
        "readable": True,
        "expected": "0400 root-owned",
    }
    assert sensitive_path_permissions_check([rec]) == []


def test_unreadable_path_reports_unknown_state():
    rec = {
        "path": "/crypto_keyfile.bin",
        "exists": True,
        "mode": None,
        "uid": None,
        "gid": None,
        "owner": None,
        "group": None,
        "readable": False,
        "expected": "0400 root-owned",
    }
    findings = sensitive_path_permissions_check([rec])
    assert len(findings) == 1
    assert findings[0].check == "security.sensitive_path_unknown"
    assert findings[0].severity is Severity.WARNING


def test_collector_sensitive_paths_missing_not_reported(tmp_path, monkeypatch):
    # point collector at tmp paths via env/monkeypatch by calling helper with explicit paths
    from volt_watch import collector

    monkeypatch.setattr(collector, "SENSITIVE_PATH_SPECS", [
        {"path": str(tmp_path / "missing"), "kind": "luks_keyfile"},
    ])
    records = collector.sensitive_path_records()
    assert records == []


def test_collector_sensitive_paths_reports_mode(tmp_path, monkeypatch):
    from volt_watch import collector

    p = tmp_path / "keyfile"
    p.write_bytes(b"x")
    os.chmod(p, 0o644)
    monkeypatch.setattr(collector, "SENSITIVE_PATH_SPECS", [
        {"path": str(p), "kind": "luks_keyfile"},
    ])
    records = collector.sensitive_path_records()
    assert len(records) == 1
    assert records[0]["path"] == str(p)
    assert records[0]["exists"] is True
    assert records[0]["readable"] is True
    assert records[0]["mode"].endswith("644")


def test_auditor_security_group_runs_sensitive_paths(monkeypatch):
    monkeypatch.setattr(auditor.collector, "empty_password_accounts", lambda: [])
    monkeypatch.setattr(auditor.collector, "sensitive_path_records", lambda: [{
        "path": "/crypto_keyfile.bin", "exists": True, "mode": "0o644", "uid": 0, "gid": 0,
        "owner": "root", "group": "root", "readable": True, "expected": "0400 root-owned",
    }])
    checks = [f.check for f in auditor.audit(only="security")]
    assert "security.sensitive_path_permissions" in checks


def test_ssh_user_private_key_too_permissive_is_critical():
    rec = {
        "path": "/home/alice/.ssh/id_ed25519",
        "exists": True,
        "mode": "0o644",
        "uid": 1000,
        "gid": 1000,
        "owner": "alice",
        "group": "alice",
        "readable": True,
        "expected": "0600 owner-owned",
    }
    findings = sensitive_path_permissions_check([rec])
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL


def test_ssh_user_private_key_group_readable_is_critical():
    rec = {
        "path": "/home/alice/.ssh/id_rsa",
        "exists": True,
        "mode": "0o640",
        "uid": 1000,
        "gid": 1000,
        "owner": "alice",
        "group": "alice",
        "readable": True,
        "expected": "0600 owner-owned",
    }
    findings = sensitive_path_permissions_check([rec])
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL


def test_ssh_user_private_key_safe_permissions_no_finding():
    rec = {
        "path": "/home/alice/.ssh/id_ed25519",
        "exists": True,
        "mode": "0o600",
        "uid": 1000,
        "gid": 1000,
        "owner": "alice",
        "group": "alice",
        "readable": True,
        "expected": "0600 owner-owned",
    }
    assert sensitive_path_permissions_check([rec]) == []


def test_collector_user_ssh_keys_pub_files_ignored(tmp_path, monkeypatch):
    from volt_watch import collector

    ssh_dir = tmp_path / "home" / "alice" / ".ssh"
    ssh_dir.mkdir(parents=True)
    (ssh_dir / "id_ed25519").write_bytes(b"x")
    os.chmod(ssh_dir / "id_ed25519", 0o600)
    (ssh_dir / "id_ed25519.pub").write_bytes(b"x")
    monkeypatch.setattr(collector, "SENSITIVE_PATH_SPECS", [
        {"path": str(tmp_path / "home" / "*" / ".ssh" / "id_*"), "kind": "ssh_user_private_key"},
    ])
    records = collector.sensitive_path_records()
    assert [r["path"] for r in records] == [str(ssh_dir / "id_ed25519")]
    assert records[0]["kind"] == "ssh_user_private_key"
