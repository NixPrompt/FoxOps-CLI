from check_result import CheckResult


def test_check_result_builds_stable_id_and_serializes_details():
    result = CheckResult(
        name="tcp_port",
        target="core-router-01:443",
        status="OK",
        message="port is open",
        details={"host": "core-router-01", "port": 443, "timeout": 3},
    )

    assert result.ok is True
    assert result.check_id == "tcp_port.core-router-01:443"
    assert result.to_dict() == {
        "check_id": "tcp_port.core-router-01:443",
        "name": "tcp_port",
        "target": "core-router-01:443",
        "status": "OK",
        "message": "port is open",
        "details": {"host": "core-router-01", "port": 443, "timeout": 3},
    }


def test_check_result_defaults_details_to_empty_dict():
    result = CheckResult("ping", "edge-fw-01", "FAIL", "no response")

    assert result.ok is False
    assert result.details == {}
    assert result.to_dict()["details"] == {}
