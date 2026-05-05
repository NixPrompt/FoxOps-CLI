import json

from check_result import CheckResult
from output_format import format_json_results


METADATA = {
    "started_at": "2026-05-05T15:42:10-07:00",
    "completed_at": "2026-05-05T15:42:14-07:00",
    "duration_ms": 4120,
    "source": "local_runner",
    "runner": "noc-runner-01",
    "platform": "Windows",
    "output_schema": "foxops.v1",
}


def test_format_json_results_returns_summary_groups_and_flat_results():
    results = [
        CheckResult(
            "ping",
            "noc-gateway",
            "OK",
            "host responded to ping",
            {"host": "noc-gateway", "timeout": 3},
        ),
        CheckResult(
            "tcp_port",
            "noc-gateway:443",
            "FAIL",
            "connection refused",
            {"host": "noc-gateway", "port": 443, "timeout": 3},
        ),
        CheckResult(
            "account_policy",
            "min_password_length",
            "WARN",
            "could not read policy",
            {"actual": None, "required": ">=12"},
        ),
        CheckResult(
            "http_status",
            "https://noc.example.com/health",
            "OK",
            "HTTP status 200",
            {"url": "https://noc.example.com/health", "host": "noc.example.com", "status_code": 200},
        ),
        CheckResult(
            "tls_certificate",
            "https://noc.example.com/health",
            "OK",
            "TLS certificate expires in 90 day(s)",
            {"url": "https://noc.example.com/health", "host": "noc.example.com", "days_remaining": 90},
        ),
    ]

    payload = json.loads(format_json_results(results, METADATA))

    assert list(payload) == ["metadata", "summary", "groups", "results"]
    assert payload["metadata"] == METADATA
    assert payload["summary"] == {"OK": 3, "WARN": 1, "FAIL": 1}
    assert set(payload) == {"metadata", "summary", "groups", "results"}
    assert set(payload["groups"]) == {"hosts", "urls", "hardening"}
    assert list(payload["groups"]["hosts"]) == ["noc-gateway"]
    assert [item["check_id"] for item in payload["groups"]["hosts"]["noc-gateway"]] == [
        "ping.noc-gateway",
        "tcp_port.noc-gateway:443",
    ]
    assert list(payload["groups"]["urls"]) == ["https://noc.example.com/health"]
    assert [item["check_id"] for item in payload["groups"]["urls"]["https://noc.example.com/health"]] == [
        "http_status.https://noc.example.com/health",
        "tls_certificate.https://noc.example.com/health",
    ]
    assert [item["check_id"] for item in payload["groups"]["hardening"]] == [
        "account_policy.min_password_length"
    ]
    assert [item["check_id"] for item in payload["results"]] == [
        "ping.noc-gateway",
        "tcp_port.noc-gateway:443",
        "account_policy.min_password_length",
        "http_status.https://noc.example.com/health",
        "tls_certificate.https://noc.example.com/health",
    ]
    assert set(payload["results"][0]) == {
        "check_id",
        "name",
        "target",
        "status",
        "message",
        "details",
    }
    assert payload["groups"]["hosts"]["noc-gateway"][0] == payload["results"][0]
    assert payload["groups"]["hardening"][0] == payload["results"][2]
    assert payload["groups"]["urls"]["https://noc.example.com/health"][0] == payload["results"][3]


def test_format_json_results_keeps_grouped_network_results_in_order_with_flat_results():
    results = [
        CheckResult(
            "dns_resolution",
            "edge-01",
            "OK",
            "resolved 1 address(es)",
            {"host": "edge-01", "timeout": 3, "addresses": ["203.0.113.10"]},
        ),
        CheckResult(
            "ping",
            "edge-01",
            "OK",
            "host responded to ping",
            {"host": "edge-01", "timeout": 3},
        ),
        CheckResult(
            "tcp_port",
            "edge-01:443",
            "FAIL",
            "connection refused",
            {"host": "edge-01", "port": 443, "timeout": 3},
        ),
        CheckResult(
            "http_status",
            "https://status.example.com/health",
            "OK",
            "HTTP status 200",
            {"url": "https://status.example.com/health", "host": "status.example.com", "status_code": 200},
        ),
        CheckResult(
            "tls_certificate",
            "https://status.example.com/health",
            "WARN",
            "TLS certificate expires in 12 day(s)",
            {
                "url": "https://status.example.com/health",
                "host": "status.example.com",
                "port": 443,
                "days_remaining": 12,
            },
        ),
    ]

    payload = json.loads(format_json_results(results, METADATA))

    flat_host_results = [
        item
        for item in payload["results"]
        if item["name"] in {"dns_resolution", "ping", "tcp_port"}
    ]
    grouped_host_results = [
        item
        for group in payload["groups"]["hosts"].values()
        for item in group
    ]
    flat_url_results = [
        item
        for item in payload["results"]
        if item["name"] in {"http_status", "tls_certificate"}
    ]
    grouped_url_results = [
        item
        for group in payload["groups"]["urls"].values()
        for item in group
    ]

    assert grouped_host_results == flat_host_results
    assert grouped_url_results == flat_url_results
