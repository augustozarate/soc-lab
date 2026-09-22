from engine.services.notification_service import (
    NotificationService,
)


class RecordingAdapter:

    def __init__(
        self,
    ):

        self.calls = []

    def send(
        self,
        plan,
        incident,
    ):

        self.calls.append(
            (
                plan,
                incident,
            )
        )

        return {
            "status": "SUCCESS",
            "backend": "recording",
        }


class FailingAdapter:

    def send(
        self,
        plan,
        incident,
    ):

        raise RuntimeError(
            "channel unavailable"
        )


def plan(
    channels,
):

    return {
        "incident_id": "incident-07d",
        "severity": "HIGH",
        "risk_score": 82.0,
        "channels": channels,
    }


def incident():

    return {
        "id": "incident-07d",
        "severity": "HIGH",
    }


def test_dispatches_to_configured_adapter():

    adapter = RecordingAdapter()

    service = NotificationService(
        adapters={
            "local": adapter,
        }
    )

    result = service.dispatch(
        plan(
            ["local"]
        ),
        incident(),
    )

    assert len(
        adapter.calls
    ) == 1

    assert result == [
        {
            "status": "SUCCESS",
            "backend": "recording",
            "channel": "local",
        }
    ]


def test_missing_adapter_is_skipped():

    service = NotificationService(
        adapters={}
    )

    result = service.dispatch(
        plan(
            ["email"]
        ),
        incident(),
    )

    assert result[0][
        "channel"
    ] == "email"

    assert result[0][
        "status"
    ] == "SKIPPED"


def test_channel_failure_is_isolated():

    healthy = RecordingAdapter()

    service = NotificationService(
        adapters={
            "email": FailingAdapter(),
            "local": healthy,
        }
    )

    result = service.dispatch(
        plan([
            "email",
            "local",
        ]),
        incident(),
    )

    assert result[0][
        "status"
    ] == "FAILED"

    assert (
        "channel unavailable"
        in result[0][
            "error"
        ]
    )

    assert result[1][
        "status"
    ] == "SUCCESS"

    assert len(
        healthy.calls
    ) == 1


def test_invalid_plan_returns_no_outcomes():

    service = NotificationService()

    assert (
        service.dispatch(
            None,
            incident(),
        )
        == []
    )


def test_channel_order_is_preserved():

    service = NotificationService(
        adapters={}
    )

    result = service.dispatch(
        plan([
            "local",
            "email",
            "telegram",
        ]),
        incident(),
    )

    assert [
        item["channel"]
        for item in result
    ] == [
        "local",
        "email",
        "telegram",
    ]


class MemoryDeliveryRepository:

    def __init__(
        self,
    ):

        self.rows = {}

    def claim(
        self,
        dedup_key,
        channel,
        incident_id=None,
        severity=None,
    ):

        key = (
            dedup_key,
            channel,
        )

        row = self.rows.get(
            key
        )

        if (
            row
            and row["status"]
            in (
                "PENDING",
                "SUCCESS",
            )
        ):

            return False

        attempts = (
            1
            if row is None
            else (
                row[
                    "attempt_count"
                ]
                + 1
            )
        )

        self.rows[key] = {
            "status": "PENDING",
            "attempt_count": attempts,
        }

        return True

    def mark_success(
        self,
        dedup_key,
        channel,
        backend=None,
    ):

        self.rows[
            (
                dedup_key,
                channel,
            )
        ][
            "status"
        ] = "SUCCESS"

        return True

    def mark_failed(
        self,
        dedup_key,
        channel,
        error,
        backend=None,
    ):

        self.rows[
            (
                dedup_key,
                channel,
            )
        ][
            "status"
        ] = "FAILED"

        return True

    def mark_skipped(
        self,
        dedup_key,
        channel,
        reason,
    ):

        self.rows[
            (
                dedup_key,
                channel,
            )
        ][
            "status"
        ] = "SKIPPED"

        return True


def durable_plan(
    channels,
):

    return {
        "incident_id": "incident-durable",
        "severity": "HIGH",
        "risk_score": 82.0,
        "dedup_key": (
            "notification:"
            "incident-durable:"
            "semantic-state"
        ),
        "channels": channels,
    }


def test_successful_delivery_is_suppressed_on_second_dispatch():

    adapter = RecordingAdapter()

    repository = (
        MemoryDeliveryRepository()
    )

    service = NotificationService(
        adapters={
            "local": adapter,
        },
        delivery_repository=repository,
    )

    first = service.dispatch(
        durable_plan(
            ["local"]
        ),
        incident(),
    )

    second = service.dispatch(
        durable_plan(
            ["local"]
        ),
        incident(),
    )

    assert first[0][
        "status"
    ] == "SUCCESS"

    assert second == [
        {
            "channel": "local",
            "status": "SUPPRESSED",
            "reason": (
                "Notification delivery "
                "already claimed or delivered"
            ),
        }
    ]

    assert len(
        adapter.calls
    ) == 1


def test_success_on_one_channel_does_not_suppress_another():

    local = RecordingAdapter()

    email = RecordingAdapter()

    repository = (
        MemoryDeliveryRepository()
    )

    service = NotificationService(
        adapters={
            "local": local,
            "email": email,
        },
        delivery_repository=repository,
    )

    result = service.dispatch(
        durable_plan([
            "local",
            "email",
        ]),
        incident(),
    )

    assert [
        item["status"]
        for item in result
    ] == [
        "SUCCESS",
        "SUCCESS",
    ]

    assert len(
        local.calls
    ) == 1

    assert len(
        email.calls
    ) == 1


def test_failed_channel_is_retryable():

    class FailOnceAdapter:

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

            if self.calls == 1:

                raise RuntimeError(
                    "temporary failure"
                )

            return {
                "status": "SUCCESS",
                "backend": "test",
            }

    adapter = FailOnceAdapter()

    repository = (
        MemoryDeliveryRepository()
    )

    service = NotificationService(
        adapters={
            "email": adapter,
        },
        delivery_repository=repository,
    )

    first = service.dispatch(
        durable_plan(
            ["email"]
        ),
        incident(),
    )

    second = service.dispatch(
        durable_plan(
            ["email"]
        ),
        incident(),
    )

    assert first[0][
        "status"
    ] == "FAILED"

    assert second[0][
        "status"
    ] == "SUCCESS"

    assert adapter.calls == 2


def test_missing_adapter_is_not_permanently_suppressed():

    repository = (
        MemoryDeliveryRepository()
    )

    service = NotificationService(
        adapters={},
        delivery_repository=repository,
    )

    first = service.dispatch(
        durable_plan(
            ["telegram"]
        ),
        incident(),
    )

    second = service.dispatch(
        durable_plan(
            ["telegram"]
        ),
        incident(),
    )

    assert first[0][
        "status"
    ] == "SKIPPED"

    assert second[0][
        "status"
    ] == "SKIPPED"

    row = repository.rows[
        (
            durable_plan(
                ["telegram"]
            )[
                "dedup_key"
            ],
            "telegram",
        )
    ]

    assert row[
        "attempt_count"
    ] == 2
