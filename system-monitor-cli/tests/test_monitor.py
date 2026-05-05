import argparse

import pytest

import monitor
from check_result import CheckResult


def test_run_network_checks_with_one_worker_preserves_host_order(monkeypatch):
    def fake_run_host_checks(host: str, port: int, timeout: int) -> list[CheckResult]:
        return [
            CheckResult("ping", host, "OK", "host responded", {"host": host}),
            CheckResult("tcp_port", f"{host}:{port}", "OK", "port is open", {"host": host, "port": port}),
        ]

    monkeypatch.setattr(monitor, "run_host_checks", fake_run_host_checks)

    results = monitor.run_network_checks(["web-01", "web-02"], port=443, timeout=1, workers=1)

    assert [result.check_id for result in results] == [
        "ping.web-01",
        "tcp_port.web-01:443",
        "ping.web-02",
        "tcp_port.web-02:443",
    ]


def test_run_network_checks_with_two_workers_preserves_submission_order(monkeypatch):
    def fake_run_host_checks(host: str, port: int, timeout: int) -> list[CheckResult]:
        return [CheckResult("ping", host, "OK", "host responded", {"host": host})]

    monkeypatch.setattr(monitor, "run_host_checks", fake_run_host_checks)

    results = monitor.run_network_checks(["web-01", "web-02", "web-03"], port=443, timeout=1, workers=2)

    assert [result.check_id for result in results] == [
        "ping.web-01",
        "ping.web-02",
        "ping.web-03",
    ]


def test_positive_int_rejects_zero_workers():
    with pytest.raises(argparse.ArgumentTypeError):
        monitor.positive_int("0")
