"""TDD: listening sockets must not vanish when `ss` is unavailable.

Issue #84 / https://github.com/volt69506-eng/volt-watch/issues/84
"""

import subprocess

from volt_watch import collector
from volt_watch.checks import listener_exposure_check
from volt_watch.severity import Severity


def _write(proc_root, name, rows):
    path = proc_root / name
    path.write_text(
        "  sl  local_address rem_address   st tx_queue:rx_queue tr:tm->when retrnsmt\n"
        + "".join(rows),
        encoding="utf-8",
    )


def _no_ss(monkeypatch):
    def fail(*args, **kwargs):
        raise FileNotFoundError("ss")

    monkeypatch.setattr(collector.subprocess, "run", fail)


def test_ss_missing_falls_back_to_proc_net_tcp(monkeypatch, tmp_path):
    # 0100007F = 127.0.0.1, 00000000 = 0.0.0.0, 1F90 = 8080.
    _no_ss(monkeypatch)
    _write(tmp_path, "tcp", [
        "   0: 00000000:1F90 00000000:0000 0A 00000000:00000000\n",  # LISTEN
        "   1: 0100007F:1F91 0100007F:1234 01 00000000:00000000\n",  # ESTABLISHED
    ])
    monkeypatch.setattr(collector, "PROC_ROOT", tmp_path)

    assert collector.listening_ports() == [
        {"address": "0.0.0.0", "port": 8080, "proto": "tcp", "process": ""}
    ]


def test_proc_fallback_covers_ipv6_and_udp(monkeypatch, tmp_path):
    _no_ss(monkeypatch)
    # :: represented as eight 32-bit little-endian words, all zero.
    _write(tmp_path, "tcp6", [
        "   0: 00000000000000000000000000000000:1F92 00000000000000000000000000000000:0000 0A\n"
    ])
    _write(tmp_path, "udp", [
        "   0: 0100007F:0035 00000000:0000 07 00000000:00000000\n"  # DNS resolver
    ])
    monkeypatch.setattr(collector, "PROC_ROOT", tmp_path)

    listeners = collector.listening_ports()
    assert listeners is not None

    assert {"address": "::", "port": 8082, "proto": "tcp"} in [
        {k: v for k, v in item.items() if k != "process"} for item in listeners
    ]
    assert {"address": "127.0.0.1", "port": 53, "proto": "udp"} in [
        {k: v for k, v in item.items() if k != "process"} for item in listeners
    ]


def test_both_sources_unavailable_returns_none_not_empty_list(monkeypatch, tmp_path):
    _no_ss(monkeypatch)
    monkeypatch.setattr(collector, "PROC_ROOT", tmp_path)

    assert collector.listening_ports() is None


def test_nonzero_ss_exit_also_uses_proc_fallback(monkeypatch, tmp_path):
    monkeypatch.setattr(
        collector.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a[0], 1, "", ""),
    )
    _write(tmp_path, "tcp", [
        "   0: 00000000:1F90 00000000:0000 0A 00000000:00000000\n"
    ])
    monkeypatch.setattr(collector, "PROC_ROOT", tmp_path)

    assert collector.listening_ports() == [
        {"address": "0.0.0.0", "port": 8080, "proto": "tcp", "process": ""}
    ]


def test_unreadable_listener_source_is_a_finding_not_silence():
    findings = listener_exposure_check(None, [], "deny")

    assert len(findings) == 1
    assert findings[0].check == "network.listeners_unreadable"
    assert findings[0].severity is Severity.WARNING
    assert "ss" in findings[0].message
    assert findings[0].evidence == {"source": "listening sockets"}
