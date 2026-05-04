import argparse
import logging
import sys
from pathlib import Path

from check_result import CheckResult
from hardening_checks import check_windows_account_hardening
from network_checks import check_host_ping, check_port_open
from output_format import format_details, format_json_results, format_text_result
from result_policy import EXIT_RUNTIME_ERROR, exit_code_for_results, normalize_hosts


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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simple host and TCP port monitoring checks.")
    parser.add_argument(
        "--host",
        action="append",
        help="Hostname or IP address to check. Repeat or comma-separate for multiple hosts.",
    )
    parser.add_argument("--port", type=int, default=443, help="TCP port to check. Default: 443.")
    parser.add_argument("--timeout", type=int, default=3, help="Timeout in seconds. Default: 3.")
    parser.add_argument(
        "--output",
        choices=["text", "json"],
        default="text",
        help="Output format. Default: text.",
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


def main() -> int:
    args = parse_args()
    hosts = normalize_hosts(args.host)

    if not hosts and not args.hardening:
        print("[FAIL] provide --host, --hardening, or both", file=sys.stderr)
        return EXIT_RUNTIME_ERROR

    try:
        configure_logging(args.log_file)
    except Exception as exc:
        print(f"[FAIL] logging setup failed: {exc}", file=sys.stderr)
        return EXIT_RUNTIME_ERROR

    checks = []

    for host in hosts:
        checks.extend([check_host_ping(host, args.timeout), check_port_open(host, args.port, args.timeout)])

    if args.hardening:
        checks.extend(check_windows_account_hardening())

    if args.output == "json":
        print(format_json_results(checks))
    else:
        for result in checks:
            print_result(result)

    for result in checks:
        log_result(result)

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
