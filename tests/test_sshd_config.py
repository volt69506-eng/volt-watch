"""Tests for issue #16: sshd's own authentication settings are never read.

The firewall check asks whether port 22 is reachable, but not whether sshd would
accept a password. On a host whose only defence is the firewall, that gap is one
rule away from a compromise.
"""

from volt_watch import collector
from volt_watch.checks import sshd_config_check


class _Result:
    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.returncode = returncode


def _run(monkeypatch, mapping):
    def fake_run(cmd, **kwargs):
        key = tuple(cmd)
        for pattern, result in mapping.items():
            if key[: len(pattern)] == pattern:
                return result
        return _Result("", 0)

    monkeypatch.setattr(collector.subprocess, "run", fake_run)


def test_password_authentication_yes_is_a_warning():
    findings = sshd_config_check({"password_authentication": True, "permit_root_login": False})

    assert [f.check for f in findings] == ["sshd.password_auth"]
    assert findings[0].severity.value == "warning"


def test_permit_root_login_yes_is_critical():
    findings = sshd_config_check({"password_authentication": False, "permit_root_login": True})

    assert [f.check for f in findings] == ["sshd.root_login"]
    assert findings[0].severity.value == "critical"


def test_unknown_settings_are_not_findings():
    assert sshd_config_check({"password_authentication": None, "permit_root_login": None}) == []


def test_key_only_configuration_is_clean():
    assert sshd_config_check({"password_authentication": False, "permit_root_login": False}) == []


def test_both_bad_settings_are_both_reported():
    findings = sshd_config_check({"password_authentication": True, "permit_root_login": True})

    assert [f.check for f in findings] == ["sshd.root_login", "sshd.password_auth"]


def test_prohibit_password_counts_as_not_root_login():
    """sshd's own default: root may sign in with a key, never with a password."""
    config = collector._parse_sshd_config("permitrootlogin prohibit-password\npasswordauthentication yes\n")

    assert config["permit_root_login"] is False
    assert config["password_authentication"] is True


def test_reader_parses_sshd_T(monkeypatch):
    text = "passwordauthentication no\npermitrootlogin no\n"
    _run(monkeypatch, {("sshd", "-T"): _Result(text, 0)})

    config = collector.sshd_config()

    assert config == {
        "password_authentication": False,
        "permit_root_login": False,
        "source": "sshd -T",
    }


def test_reader_falls_back_to_the_config_files(monkeypatch):
    """`sshd -T` needs the host keys, so an unprivileged run falls back to reading."""
    _run(monkeypatch, {("sshd", "-T"): _Result("", 1)})
    monkeypatch.setattr(
        collector,
        "_read_sshd_files",
        lambda: "PasswordAuthentication yes\nPermitRootLogin yes\n",
    )

    config = collector.sshd_config()
    assert config is not None
    assert config["password_authentication"] is True
    assert config["permit_root_login"] is True
    assert config["source"] == "files"


def test_reader_returns_none_when_nothing_can_be_read(monkeypatch):
    _run(monkeypatch, {("sshd", "-T"): _Result("", 1)})
    monkeypatch.setattr(collector, "_read_sshd_files", lambda: "")

    assert collector.sshd_config() is None
