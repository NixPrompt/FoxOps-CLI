import json

from check_result import CheckResult
from output_format import format_json_results


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
    ]

    payload = json.loads(format_json_results(results))

    assert payload["summary"] == {"OK": 1, "WARN": 1, "FAIL": 1}
    assert set(payload) == {"summary", "groups", "results"}
    assert set(payload["groups"]) == {"hosts", "hardening"}
    assert list(payload["groups"]["hosts"]) == ["noc-gateway"]
    assert [item["check_id"] for item in payload["groups"]["hosts"]["noc-gateway"]] == [
        "ping.noc-gateway",
        "tcp_port.noc-gateway:443",
    ]
    assert [item["check_id"] for item in payload["groups"]["hardening"]] == [
        "account_policy.min_password_length"
    ]
    assert [item["check_id"] for item in payload["results"]] == [
        "ping.noc-gateway",
        "tcp_port.noc-gateway:443",
        "account_policy.min_password_length",
    ]
