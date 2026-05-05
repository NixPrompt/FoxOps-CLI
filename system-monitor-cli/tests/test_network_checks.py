import socket
from urllib.error import HTTPError

import network_checks
from network_checks import check_dns_resolution, check_http_status, check_tls_certificate_expiry


def test_check_dns_resolution_returns_ok_with_unique_sorted_addresses(monkeypatch):
    def fake_getaddrinfo(host: str, port: int | None, type: int):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("203.0.113.20", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("203.0.113.10", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("203.0.113.20", 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    result = check_dns_resolution("app.example.com", timeout=3)

    assert result.name == "dns_resolution"
    assert result.target == "app.example.com"
    assert result.status == "OK"
    assert result.details == {
        "host": "app.example.com",
        "timeout": 3,
        "addresses": ["203.0.113.10", "203.0.113.20"],
    }


def test_check_dns_resolution_returns_fail_when_resolution_fails(monkeypatch):
    def fake_getaddrinfo(host: str, port: int | None, type: int):
        raise socket.gaierror("name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    result = check_dns_resolution("missing.example.com", timeout=3)

    assert result.name == "dns_resolution"
    assert result.target == "missing.example.com"
    assert result.status == "FAIL"
    assert result.details == {"host": "missing.example.com", "timeout": 3}
    assert "DNS resolution failed" in result.message


def test_check_http_status_returns_ok_for_non_error_status(monkeypatch):
    class Response:
        reason = "OK"

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def getcode(self) -> int:
            return 200

    monkeypatch.setattr(network_checks, "urlopen", lambda request, timeout: Response())

    result = check_http_status("https://example.com/status", timeout=3)

    assert result.name == "http_status"
    assert result.target == "https://example.com/status"
    assert result.status == "OK"
    assert result.details == {
        "url": "https://example.com/status",
        "timeout": 3,
        "host": "example.com",
        "status_code": 200,
        "reason": "OK",
    }


def test_check_http_status_returns_fail_for_http_error(monkeypatch):
    def fake_urlopen(request, timeout):
        raise HTTPError(request.full_url, 503, "Service Unavailable", hdrs=None, fp=None)

    monkeypatch.setattr(network_checks, "urlopen", fake_urlopen)

    result = check_http_status("https://example.com/status", timeout=3)

    assert result.name == "http_status"
    assert result.status == "FAIL"
    assert result.message == "HTTP status 503"
    assert result.details["status_code"] == 503


def test_check_tls_certificate_expiry_returns_ok_for_valid_certificate(monkeypatch):
    class RawSocket:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

    class TlsSocket:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def getpeercert(self):
            return {"notAfter": "Jan  1 00:00:00 2099 GMT"}

    class Context:
        def wrap_socket(self, raw_socket, server_hostname):
            return TlsSocket()

    monkeypatch.setattr(network_checks.socket, "create_connection", lambda address, timeout: RawSocket())
    monkeypatch.setattr(network_checks.ssl, "create_default_context", lambda: Context())

    result = check_tls_certificate_expiry("https://example.com", timeout=3)

    assert result.name == "tls_certificate"
    assert result.target == "https://example.com"
    assert result.status == "OK"
    assert result.details["host"] == "example.com"
    assert result.details["port"] == 443
    assert result.details["expires_at"] == "2099-01-01T00:00:00Z"
    assert result.details["days_remaining"] > 0


def test_check_tls_certificate_expiry_returns_fail_for_expired_certificate(monkeypatch):
    class RawSocket:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

    class TlsSocket:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def getpeercert(self):
            return {"notAfter": "Jan  1 00:00:00 2000 GMT"}

    class Context:
        def wrap_socket(self, raw_socket, server_hostname):
            return TlsSocket()

    monkeypatch.setattr(network_checks.socket, "create_connection", lambda address, timeout: RawSocket())
    monkeypatch.setattr(network_checks.ssl, "create_default_context", lambda: Context())

    result = check_tls_certificate_expiry("https://example.com", timeout=3)

    assert result.name == "tls_certificate"
    assert result.status == "FAIL"
    assert result.message == "TLS certificate is expired"


def test_check_tls_certificate_expiry_warns_for_non_https_url():
    result = check_tls_certificate_expiry("http://example.com", timeout=3)

    assert result.name == "tls_certificate"
    assert result.status == "WARN"
    assert result.message == "skipped: URL is not HTTPS"
