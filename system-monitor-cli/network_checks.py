import platform
import socket
import ssl
import subprocess
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

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


def check_http_status(url: str, timeout: int) -> CheckResult:
    """Check whether a URL returns a non-error HTTP status."""
    details = _url_details(url, timeout)
    parsed, error = _parse_http_url(url)
    if error:
        return CheckResult("http_status", url, "FAIL", error, details)

    request = Request(url, method="HEAD", headers={"User-Agent": "FoxOps-CLI"})

    try:
        with urlopen(request, timeout=timeout) as response:
            status_code = response.getcode()
            reason = getattr(response, "reason", "")
    except HTTPError as exc:
        status_code = exc.code
        reason = str(exc.reason)
    except URLError as exc:
        return CheckResult("http_status", url, "FAIL", f"HTTP request failed: {exc.reason}", details)
    except Exception as exc:
        return CheckResult("http_status", url, "FAIL", f"unexpected HTTP error: {exc}", details)

    result_details = {**details, "host": parsed.hostname, "status_code": status_code}
    if reason:
        result_details["reason"] = reason

    if status_code < 400:
        return CheckResult("http_status", url, "OK", f"HTTP status {status_code}", result_details)
    return CheckResult("http_status", url, "FAIL", f"HTTP status {status_code}", result_details)


def check_tls_certificate_expiry(url: str, timeout: int) -> CheckResult:
    """Check whether an HTTPS URL presents a currently valid certificate."""
    details = _url_details(url, timeout)
    parsed, error = _parse_http_url(url)
    if error:
        return CheckResult("tls_certificate", url, "FAIL", error, details)

    if parsed.scheme != "https":
        return CheckResult("tls_certificate", url, "WARN", "skipped: URL is not HTTPS", details)

    host = parsed.hostname
    port = parsed.port or 443

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                certificate = tls_socket.getpeercert()
    except Exception as exc:
        return CheckResult("tls_certificate", url, "FAIL", f"TLS certificate check failed: {exc}", details)

    not_after = certificate.get("notAfter")
    if not not_after:
        return CheckResult("tls_certificate", url, "FAIL", "TLS certificate did not include an expiry date", details)

    try:
        expires_at = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), timezone.utc)
    except Exception as exc:
        return CheckResult("tls_certificate", url, "FAIL", f"could not parse TLS expiry: {exc}", details)

    now = datetime.now(timezone.utc)
    days_remaining = (expires_at - now).days
    result_details = {
        **details,
        "host": host,
        "port": port,
        "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        "days_remaining": days_remaining,
    }

    if expires_at <= now:
        return CheckResult("tls_certificate", url, "FAIL", "TLS certificate is expired", result_details)
    return CheckResult(
        "tls_certificate",
        url,
        "OK",
        f"TLS certificate expires in {days_remaining} day(s)",
        result_details,
    )


def _parse_http_url(url: str):
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return parsed, "URL scheme must be http or https"
    if not parsed.hostname:
        return parsed, "URL must include a host"
    return parsed, None


def _url_details(url: str, timeout: int) -> dict:
    return {"url": url, "timeout": timeout}
