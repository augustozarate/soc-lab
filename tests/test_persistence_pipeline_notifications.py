from engine.orchestration.event_bus import (
    EventBus,
)

from engine.orchestration.pipelines.persistence_pipeline import (
    PersistencePipeline,
)


class RecordingRepository:

    def __init__(
        self,
        order,
        name,
    ):

        self.order = order
        self.name = name
        self.saved = []

    def save(
        self,
        value,
    ):

        self.order.append(
            self.name
        )

        self.saved.append(
            value
        )


class FailingRepository:

    def save(
        self,
        value,
    ):

        raise RuntimeError(
            "persistence unavailable"
        )


def test_notification_event_occurs_after_persistence():

    order = []

    incident_repository = (
        RecordingRepository(
            order,
            "incident_saved",
        )
    )

    campaign_repository = (
        RecordingRepository(
            order,
            "campaign_saved",
        )
    )

    bus = EventBus()

    payloads = []

    def subscriber(
        payload,
    ):

        order.append(
            "notification"
        )

        payloads.append(
            payload
        )

    bus.subscribe(
        "incident_persisted",
        subscriber,
    )

    pipeline = PersistencePipeline(
        incident_repository=(
            incident_repository
        ),
        campaign_repository=(
            campaign_repository
        ),
        event_bus=bus,
    )

    incident = {
        "id": "incident-persisted",
        "severity": "HIGH",
    }

    campaign = {
        "id": "campaign-1",
    }

    result = pipeline.run({
        "incident": incident,
        "campaign": campaign,
    })

    assert result is True

    assert order == [
        "incident_saved",
        "campaign_saved",
        "notification",
    ]

    assert payloads == [
        {
            "incident": incident
        }
    ]


def test_incident_save_failure_emits_no_notification():

    bus = EventBus()

    payloads = []

    bus.subscribe(
        "incident_persisted",
        payloads.append,
    )

    pipeline = PersistencePipeline(
        incident_repository=(
            FailingRepository()
        ),
        campaign_repository=(
            RecordingRepository(
                [],
                "campaign",
            )
        ),
        event_bus=bus,
    )

    try:

        pipeline.run({
            "incident": {
                "id": "incident-fail"
            }
        })

    except RuntimeError:

        pass

    else:

        raise AssertionError(
            "expected persistence failure"
        )

    assert payloads == []


def test_campaign_save_failure_emits_no_notification():

    bus = EventBus()

    payloads = []

    bus.subscribe(
        "incident_persisted",
        payloads.append,
    )

    pipeline = PersistencePipeline(
        incident_repository=(
            RecordingRepository(
                [],
                "incident",
            )
        ),
        campaign_repository=(
            FailingRepository()
        ),
        event_bus=bus,
    )

    try:

        pipeline.run({
            "incident": {
                "id": "incident-ok"
            },
            "campaign": {
                "id": "campaign-fail"
            },
        })

    except RuntimeError:

        pass

    else:

        raise AssertionError(
            "expected campaign failure"
        )

    assert payloads == []


def test_event_payload_is_snapshot_not_original_reference():

    bus = EventBus()

    def mutating_subscriber(
        payload,
    ):

        payload[
            "incident"
        ][
            "severity"
        ] = "MUTATED"

    bus.subscribe(
        "incident_persisted",
        mutating_subscriber,
    )

    pipeline = PersistencePipeline(
        incident_repository=(
            RecordingRepository(
                [],
                "incident",
            )
        ),
        campaign_repository=(
            RecordingRepository(
                [],
                "campaign",
            )
        ),
        event_bus=bus,
    )

    incident = {
        "id": "snapshot-test",
        "severity": "HIGH",
    }

    pipeline.run({
        "incident": incident
    })

    assert (
        incident["severity"]
        == "HIGH"
    )


def test_subscriber_failure_does_not_fail_persistence():

    bus = EventBus()

    received = []

    def broken(
        payload,
    ):

        raise RuntimeError(
            "notification failed"
        )

    def healthy(
        payload,
    ):

        received.append(
            payload
        )

    bus.subscribe(
        "incident_persisted",
        broken,
    )

    bus.subscribe(
        "incident_persisted",
        healthy,
    )

    pipeline = PersistencePipeline(
        incident_repository=(
            RecordingRepository(
                [],
                "incident",
            )
        ),
        campaign_repository=(
            RecordingRepository(
                [],
                "campaign",
            )
        ),
        event_bus=bus,
    )

    result = pipeline.run({
        "incident": {
            "id": "isolation"
        }
    })

    assert result is True

    assert len(
        received
    ) == 1
