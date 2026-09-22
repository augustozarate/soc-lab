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
