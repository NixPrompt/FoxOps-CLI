import platform
import socket
import subprocess

from check_result import CheckResult


def check_dns_resolution(host: str, timeout: int) -> CheckResult:
    """Check whether a host resolves to one or more IP addresses."""
    details = {"host": host, "timeout": timeout}

    try:
        address_info = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return CheckResult("dns_resolution", host, "FAIL", f"DNS resolution failed: {exc}", details)
    except OSError as exc:
        return CheckResult("dns_resolution", host, "FAIL", f"DNS resolution failed: {exc}", details)
    except Exception as exc:
        return CheckResult("dns_resolution", host, "FAIL", f"unexpected DNS error: {exc}", details)

    addresses = sorted({info[4][0] for info in address_info if info[4]})
    if not addresses:
        return CheckResult("dns_resolution", host, "FAIL", "DNS resolution returned no addresses", details)

    return CheckResult(
        "dns_resolution",
        host,
        "OK",
        f"resolved {len(addresses)} address(es)",
        {**details, "addresses": addresses},
    )


def check_host_ping(host: str, timeout: int) -> CheckResult:
    """Check whether a host responds to ping."""
    system = platform.system().lower()
    details = {"host": host, "timeout": timeout}

    if system == "windows":
        command = ["ping", "-n", "1", "-w", str(timeout * 1000), host]
    else:
        command = ["ping", "-c", "1", "-W", str(timeout), host]

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout + 2,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return CheckResult("ping", host, "FAIL", f"ping timed out after {timeout}s", details)
    except FileNotFoundError:
        return CheckResult("ping", host, "WARN", "ping command not found", details)
    except Exception as exc:
        return CheckResult("ping", host, "FAIL", f"ping failed: {exc}", details)

    if completed.returncode == 0:
        return CheckResult("ping", host, "OK", "host responded to ping", details)

    detail = completed.stderr.strip() or completed.stdout.strip() or "no response"
    return CheckResult("ping", host, "FAIL", detail.splitlines()[-1], details)


def check_port_open(host: str, port: int, timeout: int) -> CheckResult:
    """Check whether a TCP port accepts connections."""
    target = f"{host}:{port}"
    details = {"host": host, "port": port, "timeout": timeout}

    try:
        with socket.create_connection((host, port), timeout=timeout):
            return CheckResult("tcp_port", target, "OK", "port is open", details)
    except socket.timeout:
        return CheckResult("tcp_port", target, "FAIL", f"connection timed out after {timeout}s", details)
    except ConnectionRefusedError:
        return CheckResult("tcp_port", target, "FAIL", "connection refused", details)
    except OSError as exc:
        return CheckResult("tcp_port", target, "FAIL", f"connection failed: {exc}", details)
    except Exception as exc:
        return CheckResult("tcp_port", target, "FAIL", f"unexpected error: {exc}", details)
