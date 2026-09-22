from datetime import (
    datetime,
    timedelta,
    timezone,
)

from engine.services.notification_service import (
    NotificationService,
)

from engine.storage.repositories.notification_delivery_repository import (
    NotificationDeliveryRepository,
)

from engine.storage.sqlite.database import (
    Database,
)

from engine.storage.sqlite.migrations import (
    MigrationRunner,
)


class Clock:

    def __init__(
        self,
        value,
    ):

        self.value = value

    def __call__(
        self,
    ):

        return self.value

    def advance(
        self,
        seconds,
    ):

        self.value = (
            self.value
            + timedelta(
                seconds=seconds
            )
        )


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


def make_repository(
    tmp_path,
    clock,
    base=30,
    maximum=900,
):

    db = Database(
        str(
            tmp_path
            / "retry.db"
        )
    )

    MigrationRunner(
        db
    ).run()

    return NotificationDeliveryRepository(
        db,
        retry_base_seconds=base,
        retry_max_seconds=maximum,
        now_provider=clock,
    )


def plan(
    channel="email",
):

    return {
        "incident_id": "incident-retry",
        "severity": "HIGH",
        "risk_score": 82.0,
        "dedup_key": (
            "notification:"
            "incident-retry:"
            "state"
        ),
        "channels": [
            channel
        ],
    }


def incident():

    return {
        "id": "incident-retry",
        "severity": "HIGH",
    }


def test_failed_delivery_is_deferred_before_boundary(
    tmp_path,
):

    clock = Clock(
        datetime(
            2026,
            9,
            22,
            3,
            0,
            tzinfo=timezone.utc,
        )
    )

    repo = make_repository(
        tmp_path,
        clock,
        base=30,
    )

    key = plan()[
        "dedup_key"
    ]

    decision = repo.claim_delivery(
        key,
        "email",
        incident_id="incident-retry",
        severity="HIGH",
    )

    assert (
        decision["status"]
        == "CLAIMED"
    )

    assert repo.mark_failed(
        key,
        "email",
        "smtp unavailable",
        backend="smtp",
    )

    clock.advance(
        29
    )

    decision = repo.claim_delivery(
        key,
        "email",
    )

    assert (
        decision["status"]
        == "DEFERRED"
    )

    assert (
        decision["attempt_count"]
        == 1
    )


def test_retry_allowed_exactly_at_boundary(
    tmp_path,
):

    clock = Clock(
        datetime(
            2026,
            9,
            22,
            3,
            0,
            tzinfo=timezone.utc,
        )
    )

    repo = make_repository(
        tmp_path,
        clock,
        base=30,
    )

    key = plan()[
        "dedup_key"
    ]

    assert (
        repo.claim_delivery(
            key,
            "email",
        )["status"]
        == "CLAIMED"
    )

    assert repo.mark_failed(
        key,
        "email",
        "temporary",
    )

    clock.advance(
        30
    )

    decision = repo.claim_delivery(
        key,
        "email",
    )

    assert (
        decision["status"]
        == "CLAIMED"
    )

    assert (
        decision["attempt_count"]
        == 2
    )


def test_exponential_delay_uses_attempt_count(
    tmp_path,
):

    clock = Clock(
        datetime(
            2026,
            9,
            22,
            3,
            0,
            tzinfo=timezone.utc,
        )
    )

    repo = make_repository(
        tmp_path,
        clock,
        base=30,
        maximum=900,
    )

    key = plan()[
        "dedup_key"
    ]

    assert (
        repo.claim_delivery(
            key,
            "email",
        )["status"]
        == "CLAIMED"
    )

    assert repo.mark_failed(
        key,
        "email",
        "failure 1",
    )

    clock.advance(
        30
    )

    assert (
        repo.claim_delivery(
            key,
            "email",
        )["attempt_count"]
        == 2
    )

    assert repo.mark_failed(
        key,
        "email",
        "failure 2",
    )

    clock.advance(
        59
    )

    assert (
        repo.claim_delivery(
            key,
            "email",
        )["status"]
        == "DEFERRED"
    )

    clock.advance(
        1
    )

    decision = repo.claim_delivery(
        key,
        "email",
    )

    assert (
        decision["status"]
        == "CLAIMED"
    )

    assert (
        decision["attempt_count"]
        == 3
    )


def test_retry_delay_is_capped(
    tmp_path,
):

    clock = Clock(
        datetime(
            2026,
            9,
            22,
            3,
            0,
            tzinfo=timezone.utc,
        )
    )

    repo = make_repository(
        tmp_path,
        clock,
        base=30,
        maximum=60,
    )

    key = plan()[
        "dedup_key"
    ]

    assert (
        repo.claim_delivery(
            key,
            "email",
        )["status"]
        == "CLAIMED"
    )

    assert repo.mark_failed(
        key,
        "email",
        "failure 1",
    )

    clock.advance(
        30
    )

    assert (
        repo.claim_delivery(
            key,
            "email",
        )["status"]
        == "CLAIMED"
    )

    assert repo.mark_failed(
        key,
        "email",
        "failure 2",
    )

    clock.advance(
        60
    )

    assert (
        repo.claim_delivery(
            key,
            "email",
        )["status"]
        == "CLAIMED"
    )

    assert repo.mark_failed(
        key,
        "email",
        "failure 3",
    )

    clock.advance(
        59
    )

    assert (
        repo.claim_delivery(
            key,
            "email",
        )["status"]
        == "DEFERRED"
    )

    clock.advance(
        1
    )

    assert (
        repo.claim_delivery(
            key,
            "email",
        )["status"]
        == "CLAIMED"
    )


def test_zero_base_disables_retry_cooldown(
    tmp_path,
):

    clock = Clock(
        datetime(
            2026,
            9,
            22,
            3,
            0,
            tzinfo=timezone.utc,
        )
    )

    repo = make_repository(
        tmp_path,
        clock,
        base=0,
        maximum=0,
    )

    key = plan()[
        "dedup_key"
    ]

    assert (
        repo.claim_delivery(
            key,
            "email",
        )["status"]
        == "CLAIMED"
    )

    assert repo.mark_failed(
        key,
        "email",
        "failure",
    )

    decision = repo.claim_delivery(
        key,
        "email",
    )

    assert (
        decision["status"]
        == "CLAIMED"
    )

    assert (
        decision["attempt_count"]
        == 2
    )


def test_skipped_delivery_is_also_backed_off(
    tmp_path,
):

    clock = Clock(
        datetime(
            2026,
            9,
            22,
            3,
            0,
            tzinfo=timezone.utc,
        )
    )

    repo = make_repository(
        tmp_path,
        clock,
        base=30,
    )

    key = plan(
        "telegram"
    )[
        "dedup_key"
    ]

    assert (
        repo.claim_delivery(
            key,
            "telegram",
        )["status"]
        == "CLAIMED"
    )

    assert repo.mark_skipped(
        key,
        "telegram",
        "adapter missing",
    )

    decision = repo.claim_delivery(
        key,
        "telegram",
    )

    assert (
        decision["status"]
        == "DEFERRED"
    )


def test_success_remains_terminal(
    tmp_path,
):

    clock = Clock(
        datetime(
            2026,
            9,
            22,
            3,
            0,
            tzinfo=timezone.utc,
        )
    )

    repo = make_repository(
        tmp_path,
        clock,
    )

    key = plan(
        "local"
    )[
        "dedup_key"
    ]

    assert (
        repo.claim_delivery(
            key,
            "local",
        )["status"]
        == "CLAIMED"
    )

    assert repo.mark_success(
        key,
        "local",
        backend="console",
    )

    clock.advance(
        99999
    )

    decision = repo.claim_delivery(
        key,
        "local",
    )

    assert (
        decision["status"]
        == "SUPPRESSED"
    )


def test_retry_is_channel_local(
    tmp_path,
):

    clock = Clock(
        datetime(
            2026,
            9,
            22,
            3,
            0,
            tzinfo=timezone.utc,
        )
    )

    repo = make_repository(
        tmp_path,
        clock,
        base=30,
    )

    key = plan()[
        "dedup_key"
    ]

    assert (
        repo.claim_delivery(
            key,
            "email",
        )["status"]
        == "CLAIMED"
    )

    assert repo.mark_failed(
        key,
        "email",
        "smtp failed",
    )

    assert (
        repo.claim_delivery(
            key,
            "email",
        )["status"]
        == "DEFERRED"
    )

    assert (
        repo.claim_delivery(
            key,
            "local",
        )["status"]
        == "CLAIMED"
    )


def test_service_does_not_call_adapter_while_deferred(
    tmp_path,
):

    clock = Clock(
        datetime(
            2026,
            9,
            22,
            3,
            0,
            tzinfo=timezone.utc,
        )
    )

    repo = make_repository(
        tmp_path,
        clock,
        base=30,
    )

    adapter = FailOnceAdapter()

    service = NotificationService(
        adapters={
            "email": adapter,
        },
        delivery_repository=repo,
    )

    first = service.dispatch(
        plan(),
        incident(),
    )

    assert (
        first[0]["status"]
        == "FAILED"
    )

    assert adapter.calls == 1

    second = service.dispatch(
        plan(),
        incident(),
    )

    assert (
        second[0]["status"]
        == "DEFERRED"
    )

    assert adapter.calls == 1

    assert second[0][
        "retry_at"
    ] is not None

    clock.advance(
        30
    )

    third = service.dispatch(
        plan(),
        incident(),
    )

    assert (
        third[0]["status"]
        == "SUCCESS"
    )

    assert adapter.calls == 2


def test_naive_clock_is_rejected(
    tmp_path,
):

    clock = Clock(
        datetime(
            2026,
            9,
            22,
            3,
            0,
        )
    )

    repo = make_repository(
        tmp_path,
        clock,
    )

    try:

        repo.claim_delivery(
            plan()["dedup_key"],
            "email",
        )

    except ValueError as error:

        assert (
            "timezone-aware"
            in str(error)
        )

    else:

        raise AssertionError(
            "naive clock was accepted"
        )


def test_invalid_retry_configuration_rejected(
    tmp_path,
):

    db = Database(
        str(
            tmp_path
            / "invalid.db"
        )
    )

    try:

        NotificationDeliveryRepository(
            db,
            retry_base_seconds=-1,
        )

    except ValueError:

        pass

    else:

        raise AssertionError(
            "negative retry base accepted"
        )

    try:

        NotificationDeliveryRepository(
            db,
            retry_base_seconds=60,
            retry_max_seconds=30,
        )

    except ValueError:

        pass

    else:

        raise AssertionError(
            "retry max below base accepted"
        )
