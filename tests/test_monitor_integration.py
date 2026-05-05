import json
import os
import shutil
import socket
import subprocess
import sys
import threading
from datetime import datetime
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def _serve_one_tcp_connection(listener: socket.socket) -> threading.Thread:
    def serve() -> None:
        try:
            connection, _ = listener.accept()
        except OSError:
            return
        with connection:
            pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return thread


def _assert_metadata(payload: dict) -> None:
    assert list(payload) == ["metadata", "summary", "groups", "results"]
    assert set(payload["metadata"]) == {
        "started_at",
        "completed_at",
        "duration_ms",
        "source",
        "runner",
        "platform",
        "output_schema",
    }
    datetime.fromisoformat(payload["metadata"]["started_at"])
    datetime.fromisoformat(payload["metadata"]["completed_at"])
    assert isinstance(payload["metadata"]["duration_ms"], int)
    assert payload["metadata"]["duration_ms"] >= 0
    assert payload["metadata"]["source"] == "local_runner"
    assert payload["metadata"]["runner"]
    assert payload["metadata"]["platform"]
    assert payload["metadata"]["output_schema"] == "foxops.v1"


def test_monitor_json_success_path_reports_expected_cli_structure():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        server_thread = _serve_one_tcp_connection(listener)

        completed = subprocess.run(
            [
                sys.executable,
                str(PROJECT_ROOT / "monitor.py"),
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--timeout",
                "1",
                "--output",
                "json",
                "--log-file",
                os.devnull,
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        server_thread.join(timeout=2)

    assert completed.returncode == 0, completed.stderr

    payload = json.loads(completed.stdout)
    _assert_metadata(payload)
    assert set(payload["summary"]) >= {"OK", "WARN", "FAIL"}
    assert set(payload["groups"]) == {"hosts", "urls", "hardening"}
    assert "127.0.0.1" in payload["groups"]["hosts"]
    assert len(payload["results"]) == 3
    assert [result["name"] for result in payload["results"]] == ["dns_resolution", "ping", "tcp_port"]
    assert all({"check_id", "name", "target", "status", "message", "details"} <= set(result) for result in payload["results"])


def test_monitor_json_accepts_hosts_file():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        server_thread = _serve_one_tcp_connection(listener)

        completed = subprocess.run(
            [
                sys.executable,
                str(PROJECT_ROOT / "monitor.py"),
                "--hosts-file",
                str(FIXTURES_DIR / "hosts-localhost.txt"),
                "--port",
                str(port),
                "--timeout",
                "1",
                "--output",
                "json",
                "--log-file",
                os.devnull,
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        server_thread.join(timeout=2)

    assert completed.returncode == 0, completed.stderr

    payload = json.loads(completed.stdout)
    _assert_metadata(payload)
    assert set(payload["groups"]) == {"hosts", "urls", "hardening"}
    assert "127.0.0.1" in payload["groups"]["hosts"]
    assert [result["name"] for result in payload["results"]] == ["dns_resolution", "ping", "tcp_port"]


def test_monitor_json_output_file_writes_same_payload_as_stdout():
    output_root = PROJECT_ROOT / ".foxops-test-output"
    output_file = output_root / "reports" / "latest.json"
    shutil.rmtree(output_root, ignore_errors=True)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            server_thread = _serve_one_tcp_connection(listener)

            completed = subprocess.run(
                [
                    sys.executable,
                    str(PROJECT_ROOT / "monitor.py"),
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                    "--timeout",
                    "1",
                    "--output",
                    "json",
                    "--output-file",
                    str(output_file),
                    "--log-file",
                    os.devnull,
                ],
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            server_thread.join(timeout=2)

        assert completed.returncode == 0, completed.stderr
        assert output_file.read_text(encoding="utf-8") == completed.stdout
        assert json.loads(output_file.read_text(encoding="utf-8")) == json.loads(completed.stdout)
    finally:
        shutil.rmtree(output_root, ignore_errors=True)


def test_monitor_json_output_file_write_failure_returns_runtime_error():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        server_thread = _serve_one_tcp_connection(listener)

        completed = subprocess.run(
            [
                sys.executable,
                str(PROJECT_ROOT / "monitor.py"),
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--timeout",
                "1",
                "--output",
                "json",
                "--output-file",
                str(PROJECT_ROOT / "examples"),
                "--log-file",
                os.devnull,
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        server_thread.join(timeout=2)

    assert completed.returncode == 2
    assert completed.stdout == ""
    assert "[FAIL] could not write output file" in completed.stderr


def test_monitor_output_file_requires_json_output():
    completed = subprocess.run(
        [
            sys.executable,
            str(PROJECT_ROOT / "monitor.py"),
            "--host",
            "127.0.0.1",
            "--output-file",
            str(PROJECT_ROOT / ".foxops-test-output" / "report.json"),
            "--log-file",
            os.devnull,
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert completed.returncode == 2
    assert completed.stdout == ""
    assert "[FAIL] --output-file requires --output json" in completed.stderr


def test_monitor_returns_runtime_error_when_hosts_file_cannot_be_read():
    completed = subprocess.run(
        [
            sys.executable,
            str(PROJECT_ROOT / "monitor.py"),
            "--hosts-file",
            str(FIXTURES_DIR / "missing-hosts.txt"),
            "--output",
            "json",
            "--log-file",
            os.devnull,
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert completed.returncode == 2
    assert completed.stdout == ""
    assert "[FAIL] could not read hosts file" in completed.stderr


def test_monitor_rejects_zero_workers():
    completed = subprocess.run(
        [
            sys.executable,
            str(PROJECT_ROOT / "monitor.py"),
            "--host",
            "127.0.0.1",
            "--workers",
            "0",
            "--log-file",
            os.devnull,
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert completed.returncode == 2
    assert "argument --workers: must be >= 1" in completed.stderr
