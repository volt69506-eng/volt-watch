"""Tests for reading real host state."""

import json

from volt_watch import collector


class _Result:
    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.returncode = returncode


def _run(monkeypatch, mapping):
    """Route subprocess calls to a mapping of command tuple -> result."""

    def fake_run(cmd, **kwargs):
        key = tuple(cmd)
        for pattern, result in mapping.items():
            if key[: len(pattern)] == pattern:
                return result
        return _Result("", 0)

    monkeypatch.setattr(collector.subprocess, "run", fake_run)


def test_tailscale_status_is_parsed(monkeypatch):
    payload = {"Self": {"HostName": "omarchy-mini"}, "BackendState": "Running"}
    _run(monkeypatch, {("tailscale", "status", "--json"): _Result(json.dumps(payload))})

    assert collector.tailscale_status() == payload


def test_tailscale_status_returns_none_when_the_cli_is_absent(monkeypatch):
    _run(monkeypatch, {("tailscale", "status", "--json"): _Result("", 1)})

    assert collector.tailscale_status() is None


def test_ufw_rules_are_parsed(monkeypatch):
    text = (
        "Status: active\n"
        "Default: deny (incoming)\n"
        "\n"
        "To                         Action      From\n"
        "--                         ------      ----\n"
        "22/tcp on tailscale0       ALLOW IN    Anywhere\n"
        "22/tcp                     DENY IN     Anywhere\n"
    )
    _run(monkeypatch, {("ufw", "status", "verbose"): _Result(text)})

    rules = collector.ufw_rules()

    assert rules == [
        {"port": "22/tcp", "action": "ALLOW", "interface": "tailscale0", "source": "Anywhere", "address": ""},
        {"port": "22/tcp", "action": "DENY", "interface": "", "source": "Anywhere", "address": ""},
    ]


def test_ufw_rules_with_address_in_target(monkeypatch):
    # ufw may print the To column as "<address> <port>" separated by a space.
    text = (
        "Status: active\n"
        "Default: deny (incoming)\n"
        "\n"
        "To                         Action      From\n"
        "--                         ------      ----\n"
        "172.17.0.1 53/udp          ALLOW IN    172.16.0.0/12   # allow-docker-dns\n"
        "192.168.1.5 8080/tcp       REJECT IN   Anywhere\n"
        "22/tcp                     ALLOW IN    Anywhere\n"
        "22/tcp on tailscale0       ALLOW IN    Anywhere\n"
    )
    _run(monkeypatch, {("ufw", "status", "verbose"): _Result(text)})

    rules = collector.ufw_rules()

    assert rules == [
        {
            "port": "53/udp",
            "action": "ALLOW",
            "interface": "",
            "source": "172.16.0.0/12",
            "address": "172.17.0.1",
        },
        {
            "port": "8080/tcp",
            "action": "REJECT",
            "interface": "",
            "source": "Anywhere",
            "address": "192.168.1.5",
        },
        {"port": "22/tcp", "action": "ALLOW", "interface": "", "source": "Anywhere", "address": ""},
        {"port": "22/tcp", "action": "ALLOW", "interface": "tailscale0", "source": "Anywhere", "address": ""},
    ]


def test_ufw_default_policy_is_parsed(monkeypatch):
    text = "Status: active\nDefault: deny (incoming), allow (outgoing)\n"
    _run(monkeypatch, {("ufw", "status", "verbose"): _Result(text)})

    assert collector.ufw_default_incoming() == "deny"


def test_power_register_is_read(monkeypatch):
    _run(monkeypatch, {("setpci", "-s", "00:1f.0", "0xa4.b"): _Result("08\n")})

    state = collector.power_restore_state()

    assert state["present"] is True
    assert state["register"] == 0x08


def test_power_register_missing_when_the_device_is_absent(monkeypatch):
    _run(monkeypatch, {("setpci", "-s", "00:1f.0", "0xa4.b"): _Result("", 1)})

    state = collector.power_restore_state()

    assert state["present"] is False
    assert state["register"] is None


def test_unit_enabled_is_reported(monkeypatch):
    _run(monkeypatch, {("systemctl", "is-enabled", "mac-mini-power-restore.service"): _Result("enabled\n")})

    assert collector.unit_enabled("mac-mini-power-restore.service") is True


def test_unit_enabled_false_when_disabled(monkeypatch):
    _run(monkeypatch, {("systemctl", "is-enabled", "mac-mini-power-restore.service"): _Result("disabled\n", 1)})

    assert collector.unit_enabled("mac-mini-power-restore.service") is False
