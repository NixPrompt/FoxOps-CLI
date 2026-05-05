import platform
from datetime import datetime
from time import perf_counter


OUTPUT_SCHEMA = "foxops.v1"


def current_timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def current_monotonic() -> float:
    return perf_counter()


def elapsed_ms(started_at: float, completed_at: float) -> int:
    return max(0, round((completed_at - started_at) * 1000))


def build_run_metadata(started_at: str, completed_at: str, duration_ms: int) -> dict[str, str | int]:
    return {
        "started_at": started_at,
        "completed_at": completed_at,
        "duration_ms": duration_ms,
        "source": "local_runner",
        "runner": platform.node() or "unknown",
        "platform": platform.system() or "unknown",
        "output_schema": OUTPUT_SCHEMA,
    }
