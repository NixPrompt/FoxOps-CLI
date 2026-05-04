import platform
import socket
import subprocess
from dataclasses import dataclass


@dataclass
class CheckResult:
    name: str
    target: str
    ok: bool
    message: str


def check_host_ping(host: str, timeout: int) -> CheckResult:
    """Check whether a host responds to ping."""
    system = platform.system().lower()

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
        return CheckResult("ping", host, False, f"ping timed out after {timeout}s")
    except FileNotFoundError:
        return CheckResult("ping", host, False, "ping command not found")
    except Exception as exc:
        return CheckResult("ping", host, False, f"ping failed: {exc}")

    if completed.returncode == 0:
        return CheckResult("ping", host, True, "host responded to ping")

    detail = completed.stderr.strip() or completed.stdout.strip() or "no response"
    return CheckResult("ping", host, False, detail.splitlines()[-1])


def check_port_open(host: str, port: int, timeout: int) -> CheckResult:
    """Check whether a TCP port accepts connections."""
    target = f"{host}:{port}"

    try:
        with socket.create_connection((host, port), timeout=timeout):
            return CheckResult("tcp_port", target, True, "port is open")
    except socket.timeout:
        return CheckResult("tcp_port", target, False, f"connection timed out after {timeout}s")
    except ConnectionRefusedError:
        return CheckResult("tcp_port", target, False, "connection refused")
    except OSError as exc:
        return CheckResult("tcp_port", target, False, f"connection failed: {exc}")
    except Exception as exc:
        return CheckResult("tcp_port", target, False, f"unexpected error: {exc}")
