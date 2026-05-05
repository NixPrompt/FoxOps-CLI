import socket

from network_checks import check_dns_resolution


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
