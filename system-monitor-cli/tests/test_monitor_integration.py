import json
import os
import socket
import subprocess
import sys
import threading
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


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
    assert set(payload) == {"summary", "groups", "results"}
    assert set(payload["summary"]) >= {"OK", "WARN", "FAIL"}
    assert set(payload["groups"]) == {"hosts", "hardening"}
    assert "127.0.0.1" in payload["groups"]["hosts"]
    assert len(payload["results"]) == 2
    assert {result["name"] for result in payload["results"]} == {"ping", "tcp_port"}
    assert all({"check_id", "name", "target", "status", "message", "details"} <= set(result) for result in payload["results"])
