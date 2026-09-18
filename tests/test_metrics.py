from datetime import (
    datetime,
    timezone,
)

from engine.telemetry.metrics import (
    Metrics,
)


def test_start_time_is_timezone_aware_utc():
    metrics = Metrics()

    assert metrics.start_time.tzinfo is not None
    assert (
        metrics.start_time.utcoffset()
        == timezone.utc.utcoffset(
            metrics.start_time
        )
    )


def test_generated_at_uses_utc_z_format():
    snapshot = Metrics().snapshot()

    generated_at = snapshot[
        "generated_at"
    ]

    assert generated_at.endswith(
        "Z"
    )

    assert not generated_at.endswith(
        "+00:00Z"
    )


def test_generated_at_is_parseable_as_aware_utc():
    snapshot = Metrics().snapshot()

    generated_at = snapshot[
        "generated_at"
    ]

    parsed = datetime.fromisoformat(
        generated_at
    )

    assert parsed.tzinfo is not None
    assert (
        parsed.utcoffset()
        == timezone.utc.utcoffset(
            parsed
        )
    )


def test_snapshot_uptime_is_non_negative():
    snapshot = Metrics().snapshot()

    assert (
        snapshot["uptime_seconds"]
        >= 0
    )
