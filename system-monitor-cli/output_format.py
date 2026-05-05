import json

from check_result import CheckResult
from result_policy import summarize_results


HOST_CHECK_NAMES = {"dns_resolution", "ping", "tcp_port"}
URL_CHECK_NAMES = {"http_status", "tls_certificate"}
HARDENING_CHECK_NAMES = {"account_hardening", "account_policy", "capability"}


def format_details(result: CheckResult) -> str:
    return " ".join(f"{key}={value}" for key, value in result.details.items())


def format_text_result(result: CheckResult) -> str:
    detail_text = format_details(result)
    if detail_text:
        return f"[{result.status}] {result.check_id} {detail_text} - {result.message}"
    return f"[{result.status}] {result.check_id} - {result.message}"


def format_json_results(results: list[CheckResult]) -> str:
    payload = {
        "summary": summarize_results(results),
        "groups": {
            "hosts": _group_results_by_detail(results, "host", HOST_CHECK_NAMES),
            "urls": _group_results_by_detail(results, "url", URL_CHECK_NAMES),
            "hardening": [
                result.to_dict()
                for result in results
                if result.name in HARDENING_CHECK_NAMES
            ],
        },
        "results": [result.to_dict() for result in results],
    }
    return json.dumps(payload, indent=2)


def _group_results_by_detail(results: list[CheckResult], detail_key: str, check_names: set[str]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for result in results:
        if result.name not in check_names:
            continue
        group_value = result.details.get(detail_key)
        if not group_value:
            continue
        grouped.setdefault(str(group_value), []).append(result.to_dict())
    return grouped
