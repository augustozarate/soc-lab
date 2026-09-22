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

from engine.storage.repositories.notification_rate_limit_repository import (
    NotificationRateLimitRepository,
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

        self.value += timedelta(
            seconds=seconds
        )


class RecordingAdapter:

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

        return {
            "status": "SUCCESS",
            "backend": "test",
        }


def make_db(
    tmp_path,
):

    db = Database(
        str(
            tmp_path
            / "rate-limit.db"
        )
    )

    MigrationRunner(
        db
    ).run()

    return db


def test_channel_limit_allows_up_to_limit(
    tmp_path,
):

    clock = Clock(
        datetime(
            2026,
            9,
            22,
            5,
            0,
            tzinfo=timezone.utc,
        )
    )

    repo = NotificationRateLimitRepository(
        make_db(
            tmp_path
        ),
        window_seconds=60,
        limits={
            "email": 2,
        },
        now_provider=clock,
    )

    assert (
        repo.check_and_consume(
            "email"
        )["status"]
        == "ALLOWED"
    )

    assert (
        repo.check_and_consume(
            "email"
        )["status"]
        == "ALLOWED"
    )

    third = repo.check_and_consume(
        "email"
    )

    assert (
        third["status"]
        == "RATE_LIMITED"
    )


def test_window_resets_exactly_at_boundary(
    tmp_path,
):

    clock = Clock(
        datetime(
            2026,
            9,
            22,
            5,
            0,
            tzinfo=timezone.utc,
        )
    )

    repo = NotificationRateLimitRepository(
        make_db(
            tmp_path
        ),
        window_seconds=60,
        limits={
            "email": 1,
        },
        now_provider=clock,
    )

    assert (
        repo.check_and_consume(
            "email"
        )["status"]
        == "ALLOWED"
    )

    clock.advance(
        59
    )

    assert (
        repo.check_and_consume(
            "email"
        )["status"]
        == "RATE_LIMITED"
    )

    clock.advance(
        1
    )

    assert (
        repo.check_and_consume(
            "email"
        )["status"]
        == "ALLOWED"
    )


def test_channels_are_isolated(
    tmp_path,
):

    clock = Clock(
        datetime(
            2026,
            9,
            22,
            5,
            0,
            tzinfo=timezone.utc,
        )
    )

    repo = NotificationRateLimitRepository(
        make_db(
            tmp_path
        ),
        window_seconds=60,
        limits={
            "email": 1,
            "telegram": 1,
        },
        now_provider=clock,
    )

    assert (
        repo.check_and_consume(
            "email"
        )["status"]
        == "ALLOWED"
    )

    assert (
        repo.check_and_consume(
            "email"
        )["status"]
        == "RATE_LIMITED"
    )

    assert (
        repo.check_and_consume(
            "telegram"
        )["status"]
        == "ALLOWED"
    )


def test_unconfigured_channel_is_unlimited(
    tmp_path,
):

    clock = Clock(
        datetime(
            2026,
            9,
            22,
            5,
            0,
            tzinfo=timezone.utc,
        )
    )

    repo = NotificationRateLimitRepository(
        make_db(
            tmp_path
        ),
        limits={
            "email": 1,
        },
        now_provider=clock,
    )

    for _ in range(
        100
    ):

        assert (
            repo.check_and_consume(
                "local"
            )["status"]
            == "UNLIMITED"
        )


def test_zero_limit_disables_channel(
    tmp_path,
):

    clock = Clock(
        datetime(
            2026,
            9,
            22,
            5,
            0,
            tzinfo=timezone.utc,
        )
    )

    repo = NotificationRateLimitRepository(
        make_db(
            tmp_path
        ),
        limits={
            "email": 0,
        },
        now_provider=clock,
    )

    assert (
        repo.check_and_consume(
            "email"
        )["status"]
        == "RATE_LIMITED"
    )


def test_service_does_not_call_adapter_when_rate_limited(
    tmp_path,
):

    clock = Clock(
        datetime(
            2026,
            9,
            22,
            5,
            0,
            tzinfo=timezone.utc,
        )
    )

    db = make_db(
        tmp_path
    )

    delivery = (
        NotificationDeliveryRepository(
            db,
            retry_base_seconds=0,
            retry_max_seconds=0,
            now_provider=clock,
        )
    )

    limiter = NotificationRateLimitRepository(
        db,
        window_seconds=60,
        limits={
            "email": 1,
        },
        now_provider=clock,
    )

    adapter = RecordingAdapter()

    service = NotificationService(
        adapters={
            "email": adapter,
        },
        delivery_repository=delivery,
        rate_limit_repository=limiter,
    )

    first_plan = {
        "incident_id": "one",
        "severity": "HIGH",
        "dedup_key": "notification:one",
        "channels": [
            "email"
        ],
    }

    second_plan = {
        "incident_id": "two",
        "severity": "HIGH",
        "dedup_key": "notification:two",
        "channels": [
            "email"
        ],
    }

    first = service.dispatch(
        first_plan,
        {
            "id": "one"
        },
    )

    second = service.dispatch(
        second_plan,
        {
            "id": "two"
        },
    )

    assert (
        first[0]["status"]
        == "SUCCESS"
    )

    assert (
        second[0]["status"]
        == "RATE_LIMITED"
    )

    assert adapter.calls == 1

    row = delivery.get(
        "notification:two",
        "email",
    )

    assert (
        row["status"]
        == "RATE_LIMITED"
    )


def test_rate_limited_delivery_is_retryable_after_window(
    tmp_path,
):

    clock = Clock(
        datetime(
            2026,
            9,
            22,
            5,
            0,
            tzinfo=timezone.utc,
        )
    )

    db = make_db(
        tmp_path
    )

    delivery = (
        NotificationDeliveryRepository(
            db,
            retry_base_seconds=0,
            retry_max_seconds=0,
            now_provider=clock,
        )
    )

    limiter = NotificationRateLimitRepository(
        db,
        window_seconds=60,
        limits={
            "email": 1,
        },
        now_provider=clock,
    )

    adapter = RecordingAdapter()

    service = NotificationService(
        adapters={
            "email": adapter,
        },
        delivery_repository=delivery,
        rate_limit_repository=limiter,
    )

    assert (
        service.dispatch(
            {
                "incident_id": "one",
                "severity": "HIGH",
                "dedup_key": "notification:one",
                "channels": [
                    "email"
                ],
            },
            {
                "id": "one"
            },
        )[0]["status"]
        == "SUCCESS"
    )

    assert (
        service.dispatch(
            {
                "incident_id": "two",
                "severity": "HIGH",
                "dedup_key": "notification:two",
                "channels": [
                    "email"
                ],
            },
            {
                "id": "two"
            },
        )[0]["status"]
        == "RATE_LIMITED"
    )

    clock.advance(
        60
    )

    retried = service.dispatch(
        {
            "incident_id": "two",
            "severity": "HIGH",
            "dedup_key": "notification:two",
            "channels": [
                "email"
            ],
        },
        {
            "id": "two"
        },
    )

    assert (
        retried[0]["status"]
        == "SUCCESS"
    )

    assert adapter.calls == 2


def test_naive_clock_is_rejected(
    tmp_path,
):

    repo = NotificationRateLimitRepository(
        make_db(
            tmp_path
        ),
        limits={
            "email": 1,
        },
        now_provider=lambda: datetime(
            2026,
            9,
            22,
            5,
            0,
        ),
    )

    try:

        repo.check_and_consume(
            "email"
        )

    except ValueError as error:

        assert (
            "timezone-aware"
            in str(error)
        )

    else:

        raise AssertionError(
            "naive clock accepted"
        )
