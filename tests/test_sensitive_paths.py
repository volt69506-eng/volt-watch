"""TDD: sensitive local secret/state file permissions are audited."""

import os
import stat

import pytest

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


def test_ssh_authorized_keys_group_or_world_writable_is_critical():
    for mode in ("0o620", "0o642", "0o666"):
        rec = {
            "path": "/home/alice/.ssh/authorized_keys",
            "exists": True,
            "mode": mode,
            "uid": 1000,
            "gid": 1000,
            "owner": "alice",
            "group": "alice",
            "readable": True,
            "expected": "0644 or stricter (not group/world-writable)",
            "kind": "ssh_authorized_keys",
        }
        findings = sensitive_path_permissions_check([rec])
        assert len(findings) == 1
        assert findings[0].check == "security.sensitive_path_permissions"
        assert findings[0].severity is Severity.CRITICAL


def test_ssh_authorized_keys_readable_only_is_info():
    rec = {
        "path": "/home/alice/.ssh/authorized_keys",
        "exists": True,
        "mode": "0o644",
        "uid": 1000,
        "gid": 1000,
        "owner": "alice",
        "group": "alice",
        "readable": True,
        "expected": "0644 or stricter (not group/world-writable)",
        "kind": "ssh_authorized_keys",
    }
    findings = sensitive_path_permissions_check([rec])
    assert len(findings) == 1
    assert findings[0].check == "security.sensitive_path_permissions"
    assert findings[0].severity is Severity.INFO


def test_ssh_dir_group_or_world_writable_is_critical():
    for mode in ("0o720", "0o755"):
        rec = {
            "path": "/home/alice/.ssh",
            "exists": True,
            "mode": mode,
            "uid": 1000,
            "gid": 1000,
            "owner": "alice",
            "group": "alice",
            "readable": True,
            "expected": "0700 or stricter (not group/world-writable)",
            "kind": "ssh_dir",
        }
        findings = sensitive_path_permissions_check([rec])
        if mode == "0o720":
            assert len(findings) == 1
            assert findings[0].severity is Severity.CRITICAL
        else:
            assert findings == []


def test_ssh_authorized_keys_and_dir_safe_permissions_clean(tmp_path, monkeypatch):
    from volt_watch import collector

    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    auth = ssh_dir / "authorized_keys"
    auth.write_bytes(b"ssh-ed25519 AAAA\n")
    os.chmod(auth, 0o600)
    os.chmod(ssh_dir, 0o700)
    monkeypatch.setattr(collector, "HOME", tmp_path)
    monkeypatch.setattr(collector, "SENSITIVE_PATH_SPECS", [
        {"path": "~/.ssh/authorized_keys", "kind": "ssh_authorized_keys"},
        {"path": "~/.ssh", "kind": "ssh_dir"},
    ])
    records = collector.sensitive_path_records()
    assert len(records) == 2
    assert sensitive_path_permissions_check(records) == []


@pytest.mark.parametrize(
    "mode, uid, severity",
    [
        (0o460, 0, Severity.CRITICAL),
        (0o442, 0, Severity.CRITICAL),
        (0o666, 0, Severity.CRITICAL),
        (0o440, 1000, Severity.CRITICAL),
        (0o444, 0, Severity.WARNING),
        (0o440, 0, None),
        (0o400, 0, None),
    ],
)
def test_sudoers_policy_permissions(mode, uid, severity):
    rec = {
        "path": "/etc/sudoers.d/90-admin",
        "kind": "sudoers_policy",
        "exists": True,
        "mode": oct(mode),
        "uid": uid,
        "gid": 0,
        "owner": "root" if uid == 0 else "admin",
        "group": "root",
        "readable": True,
        "expected": "0440 root-owned",
    }
    findings = sensitive_path_permissions_check([rec])
    if severity is None:
        assert findings == []
    else:
        assert len(findings) == 1
        assert findings[0].check == "security.sensitive_path_permissions"
        assert findings[0].severity is severity


def test_sudoers_policy_unstatable_is_unknown():
    rec = {
        "path": "/etc/sudoers",
        "kind": "sudoers_policy",
        "exists": True,
        "readable": False,
        "mode": None,
        "uid": None,
        "gid": None,
        "owner": None,
        "group": None,
        "expected": "0440 root-owned",
    }
    findings = sensitive_path_permissions_check([rec])
    assert len(findings) == 1
    assert findings[0].check == "security.sensitive_path_unknown"
    assert findings[0].severity is Severity.WARNING


def _temporary_sudoers_specs(tmp_path, monkeypatch):
    from volt_watch import collector

    # Redirect the actual allowlist entries, so this also catches a missing main/glob spec.
    specs = [
        {**spec, "path": str(tmp_path / spec["path"].lstrip("/"))}
        for spec in collector.SENSITIVE_PATH_SPECS
        if spec["kind"] == "sudoers_policy"
    ]
    monkeypatch.setattr(collector, "SENSITIVE_PATH_SPECS", specs)
    return collector


def test_sudoers_collector_to_check_uses_metadata_without_reading_policy(tmp_path, monkeypatch):
    collector = _temporary_sudoers_specs(tmp_path, monkeypatch)
    policy = tmp_path / "etc" / "sudoers"
    include = tmp_path / "etc" / "sudoers.d" / "90-admin"
    include.parent.mkdir(parents=True)
    sentinel = "NOPASSWD: private-policy-canary"
    for path in (policy, include):
        path.write_text(sentinel)
        path.chmod(0o660)

    def refuse_contents(*args, **kwargs):
        raise AssertionError("The sensitive-path reader must not read policy contents")

    with monkeypatch.context() as guard:
        guard.setattr("builtins.open", refuse_contents)
        guard.setattr(type(policy), "read_text", refuse_contents)
        guard.setattr(type(policy), "read_bytes", refuse_contents)
        records = collector.sensitive_path_records()

    assert {r["path"] for r in records} == {str(policy), str(include)}
    assert all(r["kind"] == "sudoers_policy" for r in records)
    assert all(r["expected"] == "0440 root-owned" for r in records)
    assert all(r["mode"] == "0o660" for r in records)
    findings = sensitive_path_permissions_check(records)
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    evidence = findings[0].evidence
    assert sentinel not in str(evidence)
    assert "NOPASSWD" not in str(evidence)
    for item in evidence["paths"]:
        assert set(item) == {"path", "mode", "uid", "gid", "owner", "group", "expected", "reason"}
        metadata = os.lstat(item["path"])
        assert item["uid"] == metadata.st_uid
        assert item["gid"] == metadata.st_gid
        assert item["owner"] and item["group"]


def test_missing_sudoers_policy_paths_are_clean(tmp_path, monkeypatch):
    collector = _temporary_sudoers_specs(tmp_path, monkeypatch)
    assert sensitive_path_permissions_check(collector.sensitive_path_records()) == []


def test_sudoers_collector_stat_failure_stays_unknown(tmp_path, monkeypatch):
    collector = _temporary_sudoers_specs(tmp_path, monkeypatch)
    policy = tmp_path / "etc" / "sudoers"
    policy.parent.mkdir()
    policy.touch()
    real_lstat = os.lstat

    def denied(path, *args, **kwargs):
        if str(path) == str(policy):
            raise PermissionError("metadata unavailable")
        return real_lstat(path, *args, **kwargs)

    with monkeypatch.context() as guard:
        guard.setattr(collector.os, "lstat", denied)
        records = collector.sensitive_path_records()
    assert len(records) == 1
    findings = sensitive_path_permissions_check(records)
    assert len(findings) == 1
    assert findings[0].check == "security.sensitive_path_unknown"
    assert findings[0].evidence["path"] == str(policy)
