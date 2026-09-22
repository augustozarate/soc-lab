from copy import deepcopy

from engine.services.notification_policy import (
    NotificationPolicy,
)

from engine.orchestration.subscribers.notification_subscriber import (
    NotificationSubscriber,
)


class RecordingService:

    def __init__(
        self,
    ):

        self.calls = []

    def dispatch(
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

        return [
            {
                "channel": "local",
                "status": "SUCCESS",
            }
        ]


def incident(
    severity="HIGH",
):

    return {
        "id": "incident-subscriber",
        "severity": severity,
        "risk_score": 82,
        "alerts": [],
        "response_actions": [],
    }


def test_subscriber_evaluates_persisted_incident():

    service = RecordingService()

    subscriber = NotificationSubscriber(
        policy=NotificationPolicy(),
        service=service,
    )

    result = (
        subscriber
        .on_incident_persisted(
            {
                "incident": incident()
            }
        )
    )

    assert result == [
        {
            "channel": "local",
            "status": "SUCCESS",
        }
    ]

    assert len(
        service.calls
    ) == 1

    plan, delivered = (
        service.calls[0]
    )

    assert plan[
        "event_type"
    ] == "incident_persisted"

    assert delivered[
        "id"
    ] == "incident-subscriber"


def test_low_severity_creates_no_delivery():

    service = RecordingService()

    subscriber = NotificationSubscriber(
        policy=NotificationPolicy(),
        service=service,
    )

    result = (
        subscriber
        .on_incident_persisted(
            {
                "incident": incident(
                    "LOW"
                )
            }
        )
    )

    assert result == []

    assert service.calls == []


def test_subscriber_does_not_mutate_incident():

    service = RecordingService()

    subscriber = NotificationSubscriber(
        policy=NotificationPolicy(),
        service=service,
    )

    data = incident(
        "CRITICAL"
    )

    original = deepcopy(
        data
    )

    subscriber.on_incident_persisted(
        {
            "incident": data
        }
    )

    assert data == original


def test_invalid_payload_is_ignored():

    subscriber = NotificationSubscriber(
        policy=NotificationPolicy(),
        service=RecordingService(),
    )

    assert (
        subscriber
        .on_incident_persisted(
            None
        )
        == []
    )
