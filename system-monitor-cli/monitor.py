import argparse
import logging
import sys
from pathlib import Path

from monitor_checks import CheckResult, check_host_ping, check_port_open


def configure_logging(log_file: Path) -> None:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )


def log_result(result: CheckResult) -> None:
    status = "OK" if result.ok else "FAIL"
    logging.info(
        "check=%s target=%s status=%s message=%s",
        result.name,
        result.target,
        status,
        result.message,
    )


def print_result(result: CheckResult) -> None:
    status = "OK" if result.ok else "FAIL"
    print(f"[{status}] {result.name} {result.target} - {result.message}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simple host and TCP port monitoring checks.")
    parser.add_argument("--host", required=True, help="Hostname or IP address to check.")
    parser.add_argument("--port", type=int, default=443, help="TCP port to check. Default: 443.")
    parser.add_argument("--timeout", type=int, default=3, help="Timeout in seconds. Default: 3.")
    parser.add_argument(
        "--log-file",
        type=Path,
        default=Path("monitor.log"),
        help="Path to the results log file. Default: monitor.log",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        configure_logging(args.log_file)
    except Exception as exc:
        print(f"[FAIL] logging setup failed: {exc}", file=sys.stderr)
        return 2

    checks = [
        check_host_ping(args.host, args.timeout),
        check_port_open(args.host, args.port, args.timeout),
    ]

    for result in checks:
        print_result(result)
        log_result(result)

    return 0 if all(result.ok for result in checks) else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[FAIL] interrupted by user", file=sys.stderr)
        raise SystemExit(130)
    except Exception as exc:
        print(f"[FAIL] unexpected error: {exc}", file=sys.stderr)
        raise SystemExit(2)
