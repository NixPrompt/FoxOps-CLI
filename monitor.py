import argparse
import logging
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from check_result import CheckResult
from evidence import build_run_metadata, current_monotonic, current_timestamp, elapsed_ms
from hardening_checks import check_windows_account_hardening
from network_checks import (
    check_dns_resolution,
    check_host_ping,
    check_http_status,
    check_port_open,
    check_tls_certificate_expiry,
)
from output_format import format_details, format_json_results, format_text_result
from result_policy import EXIT_RUNTIME_ERROR, dedupe_hosts, exit_code_for_results, load_hosts_file, normalize_hosts


def configure_logging(log_file: Path) -> None:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )


def log_result(result: CheckResult) -> None:
    detail_text = format_details(result)
    logging.info(
        "check=%s status=%s %s message=%s",
        result.check_id,
        result.status,
        detail_text,
        result.message,
    )


def print_result(result: CheckResult) -> None:
    print(format_text_result(result))


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return parsed


def normalize_urls(url_args: list[str] | None) -> list[str]:
    if not url_args:
        return []
    return [url_arg.strip() for url_arg in url_args if url_arg.strip()]


def run_host_checks(host: str, port: int, timeout: int) -> list[CheckResult]:
    return [
        check_dns_resolution(host, timeout),
        check_host_ping(host, timeout),
        check_port_open(host, port, timeout),
    ]


def run_url_checks(url: str, timeout: int) -> list[CheckResult]:
    return [
        check_http_status(url, timeout),
        check_tls_certificate_expiry(url, timeout),
    ]


def run_network_checks(hosts: list[str], port: int, timeout: int, workers: int) -> list[CheckResult]:
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(run_host_checks, host, port, timeout) for host in hosts]

        results = []
        for future in futures:
            results.extend(future.result())
    return results


def run_web_checks(urls: list[str], timeout: int, workers: int) -> list[CheckResult]:
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(run_url_checks, url, timeout) for url in urls]

        results = []
        for future in futures:
            results.extend(future.result())
    return results


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simple host and TCP port monitoring checks.")
    parser.add_argument(
        "--host",
        action="append",
        help="Hostname or IP address to check. Repeat or comma-separate for multiple hosts.",
    )
    parser.add_argument(
        "--hosts-file",
        type=Path,
        help="Path to a file containing hostnames or IPs, one per line; comma-separated entries are also accepted.",
    )
    parser.add_argument(
        "--url",
        action="append",
        help="HTTP or HTTPS URL to check. Repeat for multiple URLs.",
    )
    parser.add_argument("--port", type=int, default=443, help="TCP port to check. Default: 443.")
    parser.add_argument("--timeout", type=int, default=3, help="Timeout in seconds. Default: 3.")
    parser.add_argument(
        "--workers",
        type=positive_int,
        default=1,
        help="Number of concurrent network workers. Default: 1.",
    )
    parser.add_argument(
        "--output",
        choices=["text", "json"],
        default="text",
        help="Output format. Default: text.",
    )
    parser.add_argument(
        "--output-file",
        type=Path,
        help="Write JSON output to this file path when --output json is used.",
    )
    parser.add_argument(
        "--hardening",
        action="store_true",
        help="Run read-only Windows local account hardening checks.",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=Path("monitor.log"),
        help="Path to the results log file. Default: monitor.log",
    )
    return parser.parse_args()


def write_output_file(output_file: Path, payload: str) -> None:
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(f"{payload}\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    if args.output_file and args.output != "json":
        print("[FAIL] --output-file requires --output json", file=sys.stderr)
        return EXIT_RUNTIME_ERROR

    hosts_from_file = []
    if args.hosts_file:
        try:
            hosts_from_file = load_hosts_file(args.hosts_file)
        except OSError as exc:
            print(f"[FAIL] could not read hosts file {args.hosts_file}: {exc}", file=sys.stderr)
            return EXIT_RUNTIME_ERROR

    hosts = dedupe_hosts(normalize_hosts((args.host or []) + hosts_from_file))
    urls = dedupe_hosts(normalize_urls(args.url))

    if not hosts and not urls and not args.hardening:
        print("[FAIL] provide --host, --hosts-file, --url, --hardening, or a combination", file=sys.stderr)
        return EXIT_RUNTIME_ERROR

    try:
        configure_logging(args.log_file)
    except Exception as exc:
        print(f"[FAIL] logging setup failed: {exc}", file=sys.stderr)
        return EXIT_RUNTIME_ERROR

    run_started_at = current_timestamp()
    run_started_monotonic = current_monotonic()

    checks = []
    if hosts:
        checks.extend(run_network_checks(hosts, args.port, args.timeout, args.workers))

    if urls:
        checks.extend(run_web_checks(urls, args.timeout, args.workers))

    if args.hardening:
        checks.extend(check_windows_account_hardening())

    for result in checks:
        log_result(result)

    run_completed_monotonic = current_monotonic()
    run_completed_at = current_timestamp()
    run_duration_ms = elapsed_ms(run_started_monotonic, run_completed_monotonic)
    metadata = build_run_metadata(run_started_at, run_completed_at, run_duration_ms)

    if args.output == "json":
        json_payload = format_json_results(checks, metadata)
        if args.output_file:
            try:
                write_output_file(args.output_file, json_payload)
            except OSError as exc:
                logging.error("output_file_write_failed path=%s error=%s", args.output_file, exc)
                print(f"[FAIL] could not write output file {args.output_file}: {exc}", file=sys.stderr)
                return EXIT_RUNTIME_ERROR
        print(json_payload)
    else:
        for result in checks:
            print_result(result)

    return exit_code_for_results(checks)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[FAIL] interrupted by user", file=sys.stderr)
        raise SystemExit(130)
    except Exception as exc:
        print(f"[FAIL] unexpected error: {exc}", file=sys.stderr)
        raise SystemExit(EXIT_RUNTIME_ERROR)
