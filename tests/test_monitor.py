import argparse
from pathlib import Path

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


def test_normalize_urls_strips_empty_values():
    assert monitor.normalize_urls([" https://example.com ", "", "   ", "http://status.local"]) == [
        "https://example.com",
        "http://status.local",
    ]


def test_write_output_file_creates_parent_directories(monkeypatch):
    calls = []

    def fake_mkdir(self, parents=False, exist_ok=False):
        calls.append(("mkdir", self, parents, exist_ok))

    def fake_write_text(self, text, encoding=None):
        calls.append(("write_text", self, text, encoding))

    monkeypatch.setattr(Path, "mkdir", fake_mkdir)
    monkeypatch.setattr(Path, "write_text", fake_write_text)

    monitor.write_output_file(Path("nested") / "reports" / "run.json", '{"summary": {}}')

    assert calls == [
        ("mkdir", Path("nested") / "reports", True, True),
        ("write_text", Path("nested") / "reports" / "run.json", '{"summary": {}}\n', "utf-8"),
    ]


def test_write_output_file_raises_clear_os_error_for_unwritable_path(monkeypatch):
    def fake_write_text(self, text, encoding=None):
        raise OSError("no write access")

    monkeypatch.setattr(Path, "write_text", fake_write_text)

    with pytest.raises(OSError):
        monitor.write_output_file(Path("report.json"), '{"summary": {}}')


def test_run_web_checks_preserves_submission_order(monkeypatch):
    def fake_run_url_checks(url: str, timeout: int) -> list[CheckResult]:
        return [CheckResult("http_status", url, "OK", "HTTP status 200", {"url": url})]

    monkeypatch.setattr(monitor, "run_url_checks", fake_run_url_checks)

    results = monitor.run_web_checks(
        ["https://first.example.com", "https://second.example.com"],
        timeout=1,
        workers=2,
    )

    assert [result.check_id for result in results] == [
        "http_status.https://first.example.com",
        "http_status.https://second.example.com",
    ]
