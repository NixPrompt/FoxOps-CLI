from check_result import CheckResult


EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_RUNTIME_ERROR = 2


def normalize_hosts(host_args: list[str] | None) -> list[str]:
    if not host_args:
        return []

    hosts = []
    for host_arg in host_args:
        for host in host_arg.split(","):
            cleaned = host.strip()
            if cleaned:
                hosts.append(cleaned)
    return hosts


def summarize_results(results: list[CheckResult]) -> dict[str, int]:
    summary = {"OK": 0, "WARN": 0, "FAIL": 0}
    for result in results:
        summary[result.status] = summary.get(result.status, 0) + 1
    return summary


def exit_code_for_results(results: list[CheckResult]) -> int:
    if any(result.status == "FAIL" for result in results):
        return EXIT_FINDINGS
    return EXIT_OK
