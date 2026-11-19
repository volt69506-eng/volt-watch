"""Tests for issue #15: what this node publishes is never checked.

`tailscale serve` publishes a local service to the tailnet; `tailscale funnel`
publishes it to the internet. Neither leaves a trace in `BackendState`, so the
existing Tailscale check reports a clean node while a funnel exposes it.
"""

import json

from volt_watch import collector
from volt_watch.checks import tailscale_exposure_check


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


def test_a_funnel_to_the_internet_is_critical():
    services = [{"service": "funnel", "port": "443", "target": "internet"}]

    findings = tailscale_exposure_check(services)

    assert [f.check for f in findings] == ["tailscale.exposed"]
    assert findings[0].severity.value == "critical"
    assert "443" in findings[0].message


def test_a_serve_on_the_tailnet_is_info():
    services = [{"service": "serve", "port": "8080", "target": "tailnet"}]

    findings = tailscale_exposure_check(services)

    assert findings[0].severity.value == "info"


def test_nothing_published_is_no_finding():
    assert tailscale_exposure_check([]) == []


def test_an_unknown_service_is_not_treated_as_healthy():
    """The target decides, so a missing service name does not make it pass."""
    services = [{"port": "443", "target": "internet"}]

    findings = tailscale_exposure_check(services)

    assert findings[0].severity.value == "critical"


def test_reader_reports_a_funnel(monkeypatch):
    payload = {
        "TCP": {"443": {"HTTPS": True}},
        "AllowFunnel": {"node.tailb1169f.ts.net:443": True},
    }
    _run(monkeypatch, {("tailscale", "serve", "status", "--json"): _Result(json.dumps(payload), 0)})

    services = collector.tailscale_services()

    assert services == [{"service": "funnel", "port": "443", "target": "internet"}]


def test_reader_reports_a_tailnet_serve(monkeypatch):
    payload = {
        "Web": {"node.tailb1169f.ts.net:443": {"Handlers": {"/": {"Proxy": "8080"}}}},
        "AllowFunnel": {},
    }
    _run(monkeypatch, {("tailscale", "serve", "status", "--json"): _Result(json.dumps(payload), 0)})

    services = collector.tailscale_services()

    assert services == [{"service": "serve", "port": "443", "target": "tailnet"}]


def test_reader_reports_a_funnel_on_ssh_as_critical(monkeypatch):
    payload = {"TCP": {"22": {"TCPForward": "127.0.0.1:22"}}, "AllowFunnel": {":22": True}}
    _run(monkeypatch, {("tailscale", "serve", "status", "--json"): _Result(json.dumps(payload), 0)})

    services = collector.tailscale_services()

    assert services[0]["port"] == "22"
    assert tailscale_exposure_check(services)[0].severity.value == "critical"


def test_reader_returns_empty_when_the_tool_is_absent(monkeypatch):
    def boom(cmd, **kwargs):
        raise FileNotFoundError(cmd[0])

    monkeypatch.setattr(collector.subprocess, "run", boom)

    assert collector.tailscale_services() == []
