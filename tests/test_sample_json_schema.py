import json
from pathlib import Path


SAMPLE_OUTPUT = Path(__file__).resolve().parents[1] / "examples" / "sample-output.json"
RESULT_KEYS = {"check_id", "name", "target", "status", "message", "details"}
SUMMARY_KEYS = {"OK", "WARN", "FAIL"}


def test_sample_output_json_schema_snapshot():
    payload = json.loads(SAMPLE_OUTPUT.read_text(encoding="utf-8"))

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
    assert set(payload["summary"]) == SUMMARY_KEYS
    assert list(payload["groups"]) == ["hosts", "host_summaries", "urls", "hardening"]
    assert set(payload["groups"]["host_summaries"]["example.com"]) == SUMMARY_KEYS
    assert isinstance(payload["groups"]["hosts"]["example.com"], list)
    assert all(set(result) == RESULT_KEYS for result in payload["results"])
    assert payload["groups"]["hosts"]["example.com"] == payload["results"]
