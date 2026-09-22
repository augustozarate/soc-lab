from concurrent.futures import (
    ThreadPoolExecutor,
)

from datetime import (
    datetime,
    timezone,
)

import threading

from engine.services.notification_service import (
    NotificationService,
)

from engine.storage.repositories.notification_rate_limit_repository import (
    NotificationRateLimitRepository,
)

from engine.storage.sqlite.database import (
    Database,
)

from engine.storage.sqlite.migrations import (
    MigrationRunner,
)

from engine.telemetry.metrics import (
    Metrics,
)


class RecordingAdapter:

    def __init__(
        self,
        result=None,
    ):

        self.calls = 0

        self.result = (
            result
            or {
                "status": "SUCCESS",
                "backend": "test",
            }
        )

    def send(
        self,
        plan,
        incident,
    ):

        self.calls += 1

        return dict(
            self.result
        )


class FailingAdapter:

    def __init__(
        self,
    ):

        self.calls = 0

    def send(
        self,
        plan,
        incident,
    ):

        self.calls += 1

        raise RuntimeError(
            "channel unavailable"
        )


class ClaimRepository:

    def __init__(
        self,
        decisions=None,
    ):

        self.decisions = list(
            decisions or []
        )

    def claim_delivery(
        self,
        **kwargs,
    ):

        if self.decisions:

            return self.decisions.pop(
                0
            )

        return {
            "status": "CLAIMED",
            "attempt_count": 1,
        }

    def mark_success(
        self,
        **kwargs,
    ):

        return True

    def mark_failed(
        self,
        **kwargs,
    ):

        return True

    def mark_skipped(
        self,
        **kwargs,
    ):

        return True

    def mark_rate_limited(
        self,
        **kwargs,
    ):

        return True


class RateLimiter:

    def __init__(
        self,
        decision,
    ):

        self.decision = decision

    def check_and_consume(
        self,
        channel,
    ):

        return dict(
            self.decision
        )


def plan(
    channel="email",
):

    return {
        "incident_id": "metric-incident",
        "severity": "HIGH",
        "dedup_key": (
            "notification:"
            "metric-incident:"
            "state"
        ),
        "channels": [
            channel
        ],
    }


def incident():

    return {
        "id": "metric-incident",
        "severity": "HIGH",
    }


def test_concurrent_fixed_window_never_exceeds_limit(
    tmp_path,
):

    db = Database(
        str(
            tmp_path
            / "concurrent.db"
        )
    )

    MigrationRunner(
        db
    ).run()

    fixed_now = datetime(
        2026,
        9,
        22,
        6,
        0,
        tzinfo=timezone.utc,
    )

    limit = 25
    workers = 100

    repo = NotificationRateLimitRepository(
        db,
        window_seconds=60,
        limits={
            "email": limit,
        },
        now_provider=lambda: fixed_now,
    )

    barrier = threading.Barrier(
        workers
    )

    def consume(
        _,
    ):

        barrier.wait()

        return (
            repo.check_and_consume(
                "email"
            )[
                "status"
            ]
        )

    with ThreadPoolExecutor(
        max_workers=workers
    ) as executor:

        results = list(
            executor.map(
                consume,
                range(
                    workers
                ),
            )
        )

    assert (
        results.count(
            "ALLOWED"
        )
        == limit
    )

    assert (
        results.count(
            "RATE_LIMITED"
        )
        == (
            workers
            - limit
        )
    )

    row = repo.get(
        "email"
    )

    assert row is not None

    assert (
        row[
            "delivery_count"
        ]
        == limit
    )


def test_success_metrics_are_recorded():

    collector = Metrics()

    adapter = RecordingAdapter()

    service = NotificationService(
        adapters={
            "email": adapter,
        },
        delivery_repository=(
            ClaimRepository()
        ),
        metrics_collector=collector,
    )

    result = service.dispatch(
        plan(),
        incident(),
    )

    assert (
        result[0]["status"]
        == "SUCCESS"
    )

    snapshot = (
        collector.snapshot()
    )

    counters = snapshot[
        "counters"
    ]

    assert counters[
        "notification_delivery_"
        "attempts_total"
    ] == 1

    assert counters[
        "notification_delivery_"
        "attempts_total.email"
    ] == 1

    assert counters[
        "notification_delivery_"
        "success_total"
    ] == 1

    assert counters[
        "notification_delivery_"
        "success_total.email"
    ] == 1

    observations = snapshot[
        "observations"
    ]

    assert (
        observations[
            "notification_delivery_"
            "latency_seconds"
        ][
            "email"
        ][
            "count"
        ]
        == 1
    )


def test_failed_delivery_records_attempt_and_failure():

    collector = Metrics()

    adapter = FailingAdapter()

    service = NotificationService(
        adapters={
            "email": adapter,
        },
        delivery_repository=(
            ClaimRepository()
        ),
        metrics_collector=collector,
    )

    result = service.dispatch(
        plan(),
        incident(),
    )

    assert (
        result[0]["status"]
        == "FAILED"
    )

    counters = (
        collector.snapshot()[
            "counters"
        ]
    )

    assert counters[
        "notification_delivery_"
        "attempts_total"
    ] == 1

    assert counters[
        "notification_delivery_"
        "failed_total"
    ] == 1


def test_deferred_does_not_count_adapter_attempt():

    collector = Metrics()

    adapter = RecordingAdapter()

    service = NotificationService(
        adapters={
            "email": adapter,
        },
        delivery_repository=(
            ClaimRepository(
                decisions=[
                    {
                        "status": "DEFERRED",
                        "reason": (
                            "Notification retry "
                            "backoff active"
                        ),
                        "retry_at": (
                            "2026-09-22T06:"
                            "00:30+00:00"
                        ),
                        "attempt_count": 1,
                    }
                ]
            )
        ),
        metrics_collector=collector,
    )

    result = service.dispatch(
        plan(),
        incident(),
    )

    assert (
        result[0]["status"]
        == "DEFERRED"
    )

    assert adapter.calls == 0

    counters = (
        collector.snapshot()[
            "counters"
        ]
    )

    assert counters[
        "notification_delivery_"
        "deferred_total"
    ] == 1

    assert (
        counters.get(
            "notification_delivery_"
            "attempts_total",
            0,
        )
        == 0
    )


def test_suppressed_does_not_count_adapter_attempt():

    collector = Metrics()

    adapter = RecordingAdapter()

    service = NotificationService(
        adapters={
            "email": adapter,
        },
        delivery_repository=(
            ClaimRepository(
                decisions=[
                    {
                        "status": "SUPPRESSED",
                        "reason": (
                            "Notification already "
                            "delivered"
                        ),
                    }
                ]
            )
        ),
        metrics_collector=collector,
    )

    result = service.dispatch(
        plan(),
        incident(),
    )

    assert (
        result[0]["status"]
        == "SUPPRESSED"
    )

    assert adapter.calls == 0

    counters = (
        collector.snapshot()[
            "counters"
        ]
    )

    assert counters[
        "notification_delivery_"
        "suppressed_total"
    ] == 1

    assert (
        counters.get(
            "notification_delivery_"
            "attempts_total",
            0,
        )
        == 0
    )


def test_rate_limited_does_not_count_adapter_attempt():

    collector = Metrics()

    adapter = RecordingAdapter()

    service = NotificationService(
        adapters={
            "email": adapter,
        },
        delivery_repository=(
            ClaimRepository()
        ),
        rate_limit_repository=(
            RateLimiter({
                "status": "RATE_LIMITED",
                "reason": (
                    "Notification channel "
                    "rate limit reached"
                ),
                "reset_at": (
                    "2026-09-22T06:"
                    "01:00+00:00"
                ),
            })
        ),
        metrics_collector=collector,
    )

    result = service.dispatch(
        plan(),
        incident(),
    )

    assert (
        result[0]["status"]
        == "RATE_LIMITED"
    )

    assert adapter.calls == 0

    counters = (
        collector.snapshot()[
            "counters"
        ]
    )

    assert counters[
        "notification_delivery_"
        "rate_limited_total"
    ] == 1

    assert counters[
        "notification_delivery_"
        "rate_limited_total.email"
    ] == 1

    assert (
        counters.get(
            "notification_delivery_"
            "attempts_total",
            0,
        )
        == 0
    )


def test_missing_adapter_records_skipped_without_attempt():

    collector = Metrics()

    service = NotificationService(
        adapters={},
        delivery_repository=(
            ClaimRepository()
        ),
        metrics_collector=collector,
    )

    result = service.dispatch(
        plan(
            "telegram"
        ),
        incident(),
    )

    assert (
        result[0]["status"]
        == "SKIPPED"
    )

    counters = (
        collector.snapshot()[
            "counters"
        ]
    )

    assert counters[
        "notification_delivery_"
        "skipped_total"
    ] == 1

    assert counters[
        "notification_delivery_"
        "skipped_total.telegram"
    ] == 1

    assert (
        counters.get(
            "notification_delivery_"
            "attempts_total",
            0,
        )
        == 0
    )


def test_unknown_channel_collapses_to_other_metric():

    collector = Metrics()

    adapter = RecordingAdapter()

    service = NotificationService(
        adapters={
            "custom-provider": adapter,
        },
        delivery_repository=(
            ClaimRepository()
        ),
        metrics_collector=collector,
    )

    result = service.dispatch(
        plan(
            "custom-provider"
        ),
        incident(),
    )

    assert (
        result[0]["status"]
        == "SUCCESS"
    )

    counters = (
        collector.snapshot()[
            "counters"
        ]
    )

    assert counters[
        "notification_delivery_"
        "success_total.other"
    ] == 1

    assert all(
        "metric-incident"
        not in str(key)
        for key in counters
    )

    assert all(
        "custom-provider"
        not in str(key)
        for key in counters
    )


def test_metrics_failure_never_breaks_delivery():

    class BrokenMetrics:

        def inc(
            self,
            *args,
            **kwargs,
        ):

            raise RuntimeError(
                "metrics unavailable"
            )

        def observe(
            self,
            *args,
            **kwargs,
        ):

            raise RuntimeError(
                "metrics unavailable"
            )

    adapter = RecordingAdapter()

    service = NotificationService(
        adapters={
            "email": adapter,
        },
        delivery_repository=(
            ClaimRepository()
        ),
        metrics_collector=(
            BrokenMetrics()
        ),
    )

    result = service.dispatch(
        plan(),
        incident(),
    )

    assert (
        result[0]["status"]
        == "SUCCESS"
    )

    assert adapter.calls == 1
