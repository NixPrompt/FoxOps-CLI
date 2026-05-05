from evidence import OUTPUT_SCHEMA, build_run_metadata, elapsed_ms


def test_build_run_metadata_captures_run_context(monkeypatch):
    monkeypatch.setattr("platform.node", lambda: "noc-runner-01")
    monkeypatch.setattr("platform.system", lambda: "Windows")

    metadata = build_run_metadata(
        "2026-05-05T15:42:10-07:00",
        "2026-05-05T15:42:14-07:00",
        4120,
    )

    assert metadata == {
        "started_at": "2026-05-05T15:42:10-07:00",
        "completed_at": "2026-05-05T15:42:14-07:00",
        "duration_ms": 4120,
        "source": "local_runner",
        "runner": "noc-runner-01",
        "platform": "Windows",
        "output_schema": OUTPUT_SCHEMA,
    }


def test_elapsed_ms_never_returns_negative_values():
    assert elapsed_ms(10.0, 10.125) == 125
    assert elapsed_ms(10.0, 9.0) == 0
