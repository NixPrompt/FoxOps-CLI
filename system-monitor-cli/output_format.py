import json

from check_result import CheckResult
from result_policy import summarize_results


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
            "hosts": _group_network_results_by_host(results),
            "hardening": [
                result.to_dict()
                for result in results
                if result.name in {"account_hardening", "account_policy", "capability"}
            ],
        },
        "results": [result.to_dict() for result in results],
    }
    return json.dumps(payload, indent=2)


def _group_network_results_by_host(results: list[CheckResult]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for result in results:
        host = result.details.get("host")
        if not host:
            continue
        grouped.setdefault(str(host), []).append(result.to_dict())
    return grouped
