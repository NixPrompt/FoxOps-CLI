from check_result import CheckResult
from result_policy import EXIT_FINDINGS, EXIT_OK, exit_code_for_results, normalize_hosts, summarize_results


def test_normalize_hosts_accepts_repeated_and_comma_separated_values():
    assert normalize_hosts([" web-01, web-02 ", "db-01", " , cache-01,"]) == [
        "web-01",
        "web-02",
        "db-01",
        "cache-01",
    ]


def test_normalize_hosts_handles_missing_or_empty_input():
    assert normalize_hosts(None) == []
    assert normalize_hosts([]) == []
    assert normalize_hosts([" , "]) == []


def test_summarize_results_counts_standard_statuses_and_preserves_unknowns():
    results = [
        CheckResult("ping", "web-01", "OK", "host responded"),
        CheckResult("tcp_port", "web-01:443", "FAIL", "connection refused"),
        CheckResult("capability", "hardening", "WARN", "skipped"),
        CheckResult("custom", "sensor", "UNKNOWN", "unexpected status"),
    ]

    assert summarize_results(results) == {"OK": 1, "WARN": 1, "FAIL": 1, "UNKNOWN": 1}


def test_exit_code_for_results_only_reports_findings_for_failures():
    assert exit_code_for_results([]) == EXIT_OK
    assert exit_code_for_results([CheckResult("ping", "web-01", "WARN", "ping command not found")]) == EXIT_OK
    assert (
        exit_code_for_results(
            [
                CheckResult("ping", "web-01", "OK", "host responded"),
                CheckResult("tcp_port", "web-01:443", "FAIL", "connection refused"),
            ]
        )
        == EXIT_FINDINGS
    )
