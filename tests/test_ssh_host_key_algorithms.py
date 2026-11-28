"""Only bounded public host-key metadata may cross the collector/evidence boundary."""

import json
from pathlib import Path
import shutil
import subprocess

import pytest

from volt_watch import auditor, checks, collector
from volt_watch.severity import Severity


@pytest.fixture(autouse=True)
def clear_collector_errors():
    collector.collector_errors()
    yield
    collector.collector_errors()


def public_key(tmp_path, monkeypatch, name="rsa", prefix="ssh-rsa"):
    path = tmp_path / f"ssh_host_{name}_key.pub"
    path.write_text(f"{prefix} AAAAPUBLIC sensitive-comment\n", encoding="ascii")
    monkeypatch.setattr(collector, "SSH_HOST_KEY_DIR", tmp_path, raising=False)
    return path


@pytest.mark.parametrize("algorithm,bits,prefix,weak", [
    ("ED25519", 256, "ssh-ed25519", False),
    ("RSA", 4096, "ssh-rsa", False),
    ("RSA", 2048, "ssh-rsa", False),
    ("RSA", 1024, "ssh-rsa", True),
    ("DSA", 1024, "ssh-dss", True),
])
def test_public_metadata_drives_policy_without_fingerprint_or_comment(tmp_path, monkeypatch, algorithm, bits, prefix, weak):
    path = public_key(tmp_path, monkeypatch, prefix=prefix)
    calls = []

    def run(cmd, *args, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, f"{bits} SHA256:SENSITIVE_FINGERPRINT private-comment ({algorithm})\n", "SENSITIVE_STDERR")

    monkeypatch.setattr(collector, "_run", run)
    records = collector.ssh_host_key_algorithms()
    assert records == [{"path": str(path), "algorithm": algorithm, "bits": bits}]
    assert calls == [["ssh-keygen", "-l", "-f", str(path)]]
    findings = checks.ssh_host_key_algorithms_check(records)
    assert len(findings) == int(weak)
    if weak:
        assert findings[0].check == "security.ssh_host_key_weak_algorithm"
        assert findings[0].severity is Severity.WARNING
        assert findings[0].evidence == {"path": str(path), "algorithm": algorithm, "bits": bits}
    report = json.dumps([f.as_dict() for f in findings]) + repr(records)
    for secret in ["SENSITIVE_FINGERPRINT", "private-comment", "SENSITIVE_STDERR", "AAAAPUBLIC"]:
        assert secret not in report


@pytest.mark.parametrize("output", ["", "private-command-output", "1024 SHA256:secret comment (FUTURE)", "1024 SHA256:secret comment (RSA)\n1024 SHA256:secret comment (DSA)"])
def test_malformed_or_unsupported_metadata_is_unknown(tmp_path, monkeypatch, output):
    public_key(tmp_path, monkeypatch)
    monkeypatch.setattr(collector, "_run", lambda *a, **kw: subprocess.CompletedProcess([], 0, output, "PRIVATE"))
    assert collector.ssh_host_key_algorithms() is None
    assert checks.ssh_host_key_algorithms_check(None) == []
    assert "ssh_host_key_algorithms" in collector.collector_errors()


@pytest.mark.parametrize("reason", [FileNotFoundError("PRIVATE"), PermissionError("PRIVATE"), subprocess.TimeoutExpired("PRIVATE", 5)])
def test_command_failure_is_unknown_and_does_not_leak(tmp_path, monkeypatch, reason):
    public_key(tmp_path, monkeypatch)

    def failed(*args, **kwargs):
        raise reason

    monkeypatch.setattr(collector.subprocess, "run", failed)
    assert collector.ssh_host_key_algorithms() is None
    assert "PRIVATE" not in repr(collector.collector_errors())


def test_nonzero_command_exit_is_unknown(tmp_path, monkeypatch):
    public_key(tmp_path, monkeypatch)
    monkeypatch.setattr(collector, "_run", lambda *a, **kw: subprocess.CompletedProcess([], 1, "PRIVATE_STDOUT", "PRIVATE_STDERR"))
    assert collector.ssh_host_key_algorithms() is None
    errors = collector.collector_errors()
    assert "ssh_host_key_algorithms" in errors
    assert "PRIVATE" not in repr(errors)


def test_empty_public_directory_is_unknown(tmp_path, monkeypatch):
    monkeypatch.setattr(collector, "SSH_HOST_KEY_DIR", tmp_path, raising=False)
    assert collector.ssh_host_key_algorithms() is None
    assert "ssh_host_key_algorithms" in collector.collector_errors()


def test_private_paths_symlinks_and_misnamed_private_headers_never_reach_command(tmp_path, monkeypatch):
    private = tmp_path / "ssh_host_rsa_key"
    private.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nPRIVATE_SECRET\n")
    (tmp_path / "ssh_host_link_key.pub").symlink_to(private)
    (tmp_path / "ssh_host_misnamed_key.pub").write_bytes(private.read_bytes())
    monkeypatch.setattr(collector, "SSH_HOST_KEY_DIR", tmp_path, raising=False)
    monkeypatch.setattr(collector, "_run", lambda *a, **kw: pytest.fail("not a public key"))
    assert collector.ssh_host_key_algorithms() is None
    assert "PRIVATE_SECRET" not in repr(collector.collector_errors())


def test_known_weak_key_survives_another_unknown_public_key(tmp_path, monkeypatch):
    path = public_key(tmp_path, monkeypatch, "a")
    (tmp_path / "ssh_host_z_key.pub").write_text("not a public key\n")
    monkeypatch.setattr(collector, "_run", lambda *a, **kw: subprocess.CompletedProcess([], 0, "1024 SHA256:secret comment (RSA)\n", ""))
    records = collector.ssh_host_key_algorithms()
    assert checks.ssh_host_key_algorithms_check(records)[0].evidence["path"] == str(path)
    assert "ssh_host_key_algorithms" in collector.collector_errors()


def test_unknown_reader_makes_audit_degraded_without_weak_finding(tmp_path, monkeypatch):
    monkeypatch.setattr(collector, "SSH_HOST_KEY_DIR", tmp_path, raising=False)
    monkeypatch.setattr(auditor, "CHECKS", {"security": [lambda: checks.ssh_host_key_algorithms_check(collector.ssh_host_key_algorithms())]})
    findings, coverage = auditor.audit_with_coverage(only="security")
    assert [f.check for f in findings] == ["auditor.degraded"]
    assert coverage["degraded"] == ["ssh_host_key_algorithms"]


def test_finding_is_registered_in_security_without_host_reads():
    security = next(group for group in auditor.list_checks() if group["group"] == "security")
    assert "security.ssh_host_key_weak_algorithm" in security["findings"]


@pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="ssh-keygen unavailable")
@pytest.mark.parametrize("kind,bits,weak", [("ed25519", None, False), ("rsa", 1024, True), ("rsa", 4096, False)])
def test_real_ssh_keygen_reads_only_generated_temp_public_metadata(tmp_path, monkeypatch, kind, bits, weak):
    key = tmp_path / f"ssh_host_{kind}_key"
    command = ["ssh-keygen", "-q", "-t", kind, "-N", "", "-C", "SENSITIVE_COMMENT", "-f", str(key)]
    if bits:
        command += ["-b", str(bits)]
    subprocess.run(command, check=True, capture_output=True, timeout=30)
    monkeypatch.setattr(collector, "SSH_HOST_KEY_DIR", tmp_path, raising=False)
    records = collector.ssh_host_key_algorithms()
    assert records and records[0]["path"] == str(key) + ".pub"
    assert records[0]["algorithm"] == kind.upper()
    assert records[0]["bits"] == (bits or 256)
    assert len(checks.ssh_host_key_algorithms_check(records)) == int(weak)
    assert "SENSITIVE_COMMENT" not in repr(records)


def test_dsa_public_blob_is_detected_when_keygen_no_longer_supports_dsa(tmp_path, monkeypatch):
    fixture = Path(__file__).with_name("fixtures") / "ssh_host_dsa_key.pub"
    public = tmp_path / fixture.name
    public.write_bytes(fixture.read_bytes())
    monkeypatch.setattr(collector, "SSH_HOST_KEY_DIR", tmp_path, raising=False)
    monkeypatch.setattr(collector, "_run", lambda *a, **kw: subprocess.CompletedProcess([], 1, "", "not supported PRIVATE"))
    records = collector.ssh_host_key_algorithms()
    assert records == [{"path": str(public), "algorithm": "DSA", "bits": 1024}]
    assert checks.ssh_host_key_algorithms_check(records)[0].severity is Severity.WARNING
    assert collector.collector_errors() == {}


@pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="ssh-keygen unavailable")
def test_real_keygen_or_bounded_fallback_recognises_legacy_dsa(tmp_path, monkeypatch):
    fixture = Path(__file__).with_name("fixtures") / "ssh_host_dsa_key.pub"
    public = tmp_path / fixture.name
    public.write_bytes(fixture.read_bytes())
    monkeypatch.setattr(collector, "SSH_HOST_KEY_DIR", tmp_path, raising=False)
    records = collector.ssh_host_key_algorithms()
    assert records == [{"path": str(public), "algorithm": "DSA", "bits": 1024}]
    assert len(checks.ssh_host_key_algorithms_check(records)) == 1


@pytest.mark.parametrize("kind", ["oversized", "directory", "unreadable"])
def test_unavailable_public_files_never_reach_ssh_keygen(tmp_path, monkeypatch, kind):
    path = public_key(tmp_path, monkeypatch)
    if kind == "oversized":
        path.write_bytes(b"ssh-rsa " + b"x" * collector.MAX_SSH_PUBLIC_KEY_BYTES)
    elif kind == "directory":
        path.unlink()
        path.mkdir()
    else:
        def denied(*args, **kwargs):
            raise PermissionError("PRIVATE")
        monkeypatch.setattr(collector.os, "open", denied)
    monkeypatch.setattr(collector, "_run", lambda *a, **kw: pytest.fail("file is not inspectable"))
    assert collector.ssh_host_key_algorithms() is None
    assert "PRIVATE" not in repr(collector.collector_errors())


def test_missing_public_directory_is_unknown(tmp_path, monkeypatch):
    monkeypatch.setattr(collector, "SSH_HOST_KEY_DIR", tmp_path / "missing")
    assert collector.ssh_host_key_algorithms() is None
    assert "ssh_host_key_algorithms" in collector.collector_errors()


@pytest.mark.parametrize("limit", ["MAX_SSH_HOST_KEYS", "MAX_SSH_KEY_DIRECTORY_ENTRIES"])
def test_scan_and_command_counts_are_bounded(tmp_path, monkeypatch, limit):
    for i in range(5):
        public_key(tmp_path, monkeypatch, str(i))
    monkeypatch.setattr(collector, limit, 2)
    calls = []

    def run(cmd, *args, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "1024 SHA256:secret comment (RSA)\n", "")

    monkeypatch.setattr(collector, "_run", run)
    records = collector.ssh_host_key_algorithms()
    assert len(records) <= 2
    assert len(calls) <= 2
    assert "limit" in collector.collector_errors()["ssh_host_key_algorithms"]["reason"]


def test_private_header_read_does_not_buffer_or_read_private_body(tmp_path, monkeypatch):
    path = tmp_path / "ssh_host_misnamed_key.pub"
    header = b"-----BEGIN OPENSSH PRIVATE KEY-----\n"
    path.write_bytes(header + b"PRIVATE_BODY_MUST_NOT_BE_READ\n")
    positions = []
    real = collector.os.fdopen

    class ObservedFile:
        def __init__(self, stream):
            self.stream = stream
        def __enter__(self):
            self.stream.__enter__()
            return self
        def __exit__(self, *args):
            return self.stream.__exit__(*args)
        def fileno(self):
            return self.stream.fileno()
        def readline(self, limit):
            result = self.stream.readline(limit)
            positions.append(self.stream.tell())
            return result

    def observed(fd, mode, buffering):
        assert buffering == 0
        return ObservedFile(real(fd, mode, buffering))

    monkeypatch.setattr(collector.os, "fdopen", observed)
    assert collector._ssh_public_key(path) is None
    assert positions == [len(header)]


@pytest.mark.parametrize("line", [b"ssh-dss not-base64", b"ssh-dss AAAA", b"ssh-dss AAAAAA==", b"ssh-rsa AAAA"])
def test_malformed_dsa_public_blobs_are_unknown(line):
    assert collector._dsa_public_bits(line) is None


def test_dsa_still_needs_an_available_ssh_keygen(tmp_path, monkeypatch):
    fixture = Path(__file__).with_name("fixtures") / "ssh_host_dsa_key.pub"
    (tmp_path / fixture.name).write_bytes(fixture.read_bytes())
    monkeypatch.setattr(collector, "SSH_HOST_KEY_DIR", tmp_path)

    def missing(*args, **kwargs):
        raise FileNotFoundError("PRIVATE")

    monkeypatch.setattr(collector.subprocess, "run", missing)
    assert collector.ssh_host_key_algorithms() is None
    errors = collector.collector_errors()
    assert errors["ssh_host_key_algorithms"]["kind"] == "missing_tool"
    assert "PRIVATE" not in repr(errors)


@pytest.mark.parametrize("damage", ["truncated_length", "truncated_value", "trailing", "wrong_type", "negative_p", "empty_q"])
def test_dsa_wire_fields_must_be_complete_positive_and_have_no_trailing_bytes(damage):
    import base64
    import struct

    parts = [b"ssh-dss", b"\x00\x80", b"\x01", b"\x02", b"\x03"]
    if damage == "wrong_type":
        parts[0] = b"ssh-rsa"
    elif damage == "negative_p":
        parts[1] = b"\xff"
    elif damage == "empty_q":
        parts[2] = b""
    blob = b"".join(struct.pack(">I", len(part)) + part for part in parts)
    if damage == "truncated_length":
        blob = blob[:2]
    elif damage == "truncated_value":
        blob = blob[:-1]
    elif damage == "trailing":
        blob += b"extra"
    assert collector._dsa_public_bits(b"ssh-dss " + base64.b64encode(blob)) is None
