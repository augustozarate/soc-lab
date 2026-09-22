from datetime import (
    datetime,
    timedelta,
    timezone,
)

from engine.services.telegram_notification_adapter import (
    TelegramNotificationAdapter,
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


def make_db(
    tmp_path,
    filename="provider.db",
):

    db = Database(
        str(
            tmp_path
            / filename
        )
    )

    MigrationRunner(
        db
    ).run()

    return db


def make_repository(
    tmp_path,
    clock,
    base=30,
    maximum=900,
):

    return NotificationDeliveryRepository(
        make_db(
            tmp_path
        ),
        retry_base_seconds=base,
        retry_max_seconds=maximum,
        now_provider=clock,
    )


def test_new_schema_contains_provider_retry_at(
    tmp_path,
):

    db = make_db(
        tmp_path
    )

    with db.connect() as conn:

        columns = {
            row[
                "name"
            ]
            for row in conn.execute(
                """
                PRAGMA table_info(
                    notification_deliveries
                )
                """
            ).fetchall()
        }

    assert (
        "provider_retry_at"
        in columns
    )


def test_legacy_schema_is_migrated_additively(
    tmp_path,
):

    db = Database(
        str(
            tmp_path
            / "legacy.db"
        )
    )

    with db.connect() as conn:

        conn.execute(
            """
            CREATE TABLE
            notification_deliveries (
                dedup_key TEXT NOT NULL,
                channel TEXT NOT NULL,
                incident_id TEXT,
                severity TEXT,
                status TEXT NOT NULL,
                backend TEXT,
                attempt_count INTEGER
                    NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_attempt_at TEXT,
                delivered_at TEXT,
                last_error TEXT,
                PRIMARY KEY (
                    dedup_key,
                    channel
                )
            )
            """
        )

    MigrationRunner(
        db
    ).run()

    with db.connect() as conn:

        columns = {
            row[
                "name"
            ]
            for row in conn.execute(
                """
                PRAGMA table_info(
                    notification_deliveries
                )
                """
            ).fetchall()
        }

    assert (
        "provider_retry_at"
        in columns
    )


def test_provider_retry_boundary_is_persisted(
    tmp_path,
):

    clock = Clock(
        datetime(
            2026,
            9,
            22,
            12,
            0,
            tzinfo=timezone.utc,
        )
    )

    repo = make_repository(
        tmp_path,
        clock,
    )

    key = (
        "notification:"
        "provider-persist"
    )

    assert (
        repo.claim_delivery(
            key,
            "telegram",
        )["status"]
        == "CLAIMED"
    )

    assert repo.mark_rate_limited(
        key,
        "telegram",
        (
            "Telegram delivery "
            "rate limited"
        ),
        retry_after_seconds=60,
    )

    row = repo.get(
        key,
        "telegram",
    )

    expected = (
        clock.value
        + timedelta(
            seconds=60
        )
    ).isoformat(
        timespec="microseconds"
    )

    assert (
        row[
            "provider_retry_at"
        ]
        == expected
    )


def test_provider_retry_defers_before_boundary(
    tmp_path,
):

    clock = Clock(
        datetime(
            2026,
            9,
            22,
            12,
            0,
            tzinfo=timezone.utc,
        )
    )

    repo = make_repository(
        tmp_path,
        clock,
        base=30,
    )

    key = (
        "notification:"
        "provider-defer"
    )

    repo.claim_delivery(
        key,
        "telegram",
    )

    repo.mark_rate_limited(
        key,
        "telegram",
        "provider rate limit",
        retry_after_seconds=60,
    )

    clock.advance(
        30
    )

    decision = repo.claim_delivery(
        key,
        "telegram",
    )

    assert (
        decision["status"]
        == "DEFERRED"
    )

    assert (
        decision["reason"]
        == (
            "Provider retry "
            "boundary active"
        )
    )

    expected = datetime(
        2026,
        9,
        22,
        12,
        1,
        tzinfo=timezone.utc,
    ).isoformat(
        timespec="microseconds"
    )

    assert (
        decision["retry_at"]
        == expected
    )


def test_provider_retry_claims_exactly_at_boundary(
    tmp_path,
):

    clock = Clock(
        datetime(
            2026,
            9,
            22,
            12,
            0,
            tzinfo=timezone.utc,
        )
    )

    repo = make_repository(
        tmp_path,
        clock,
        base=900,
        maximum=900,
    )

    key = (
        "notification:"
        "provider-boundary"
    )

    repo.claim_delivery(
        key,
        "telegram",
    )

    repo.mark_rate_limited(
        key,
        "telegram",
        "provider rate limit",
        retry_after_seconds=60,
    )

    clock.advance(
        60
    )

    decision = repo.claim_delivery(
        key,
        "telegram",
    )

    assert (
        decision["status"]
        == "CLAIMED"
    )

    assert (
        decision[
            "attempt_count"
        ]
        == 2
    )

    row = repo.get(
        key,
        "telegram",
    )

    assert (
        row[
            "provider_retry_at"
        ]
        is None
    )


def test_rate_limited_without_provider_boundary_uses_legacy_backoff(
    tmp_path,
):

    clock = Clock(
        datetime(
            2026,
            9,
            22,
            12,
            0,
            tzinfo=timezone.utc,
        )
    )

    repo = make_repository(
        tmp_path,
        clock,
        base=30,
    )

    key = (
        "notification:"
        "legacy-rate-limit"
    )

    repo.claim_delivery(
        key,
        "telegram",
    )

    repo.mark_rate_limited(
        key,
        "telegram",
        "legacy rate limit",
    )

    clock.advance(
        29
    )

    assert (
        repo.claim_delivery(
            key,
            "telegram",
        )["status"]
        == "DEFERRED"
    )

    clock.advance(
        1
    )

    assert (
        repo.claim_delivery(
            key,
            "telegram",
        )["status"]
        == "CLAIMED"
    )


def test_invalid_retry_after_is_rejected_by_repository(
    tmp_path,
):

    clock = Clock(
        datetime(
            2026,
            9,
            22,
            12,
            0,
            tzinfo=timezone.utc,
        )
    )

    values = (
        0,
        -1,
        86401,
        True,
        "60",
        1.5,
    )

    for index, value in enumerate(
        values
    ):

        repo = (
            NotificationDeliveryRepository(
                make_db(
                    tmp_path,
                    (
                        "invalid-"
                        + str(index)
                        + ".db"
                    ),
                ),
                now_provider=clock,
            )
        )

        key = (
            "notification:"
            "invalid-"
            + str(index)
        )

        repo.claim_delivery(
            key,
            "telegram",
        )

        try:

            repo.mark_rate_limited(
                key,
                "telegram",
                "provider rate limit",
                retry_after_seconds=value,
            )

        except ValueError:

            pass

        else:

            raise AssertionError(
                (
                    "invalid retry_after "
                    f"accepted: {value!r}"
                )
            )


def test_telegram_invalid_retry_after_falls_back_without_leak():

    token = (
        "123456:"
        "PRIVATE-RETRY-TOKEN"
    )

    class Response:

        status_code = 429

        def json(
            self,
        ):

            return {
                "ok": False,
                "description": (
                    "DO-NOT-PERSIST"
                ),
                "parameters": {
                    "retry_after": "60",
                },
            }

    adapter = TelegramNotificationAdapter(
        bot_token=token,
        chat_id="-100123",
        post=(
            lambda *args, **kwargs:
            Response()
        ),
    )

    result = adapter.send(
        {
            "incident_id": "retry",
            "severity": "HIGH",
            "risk_score": 80,
        },
        {
            "alerts": [],
            "response_actions": [],
        },
    )

    assert (
        result["status"]
        == "RATE_LIMITED"
    )

    assert (
        "retry_after_seconds"
        not in result
    )

    serialized = str(
        result
    )

    assert token not in serialized

    assert (
        "DO-NOT-PERSIST"
        not in serialized
    )


# ============================================================
# NOTIFICATION SERVICE INTEGRATION
# ============================================================

from engine.services.notification_service import (
    NotificationService,
)


class ProviderRateLimitedAdapter:

    def __init__(
        self,
        retry_after_seconds=60,
    ):

        self.retry_after_seconds = (
            retry_after_seconds
        )

        self.calls = 0

    def send(
        self,
        plan,
        incident,
    ):

        self.calls += 1

        return {
            "channel": "telegram",
            "status": "RATE_LIMITED",
            "backend": (
                "telegram_bot_api"
            ),
            "http_status": 429,
            "reason": (
                "Telegram delivery "
                "rate limited"
            ),
            "retry_after_seconds": (
                self.retry_after_seconds
            ),
        }


def provider_plan():

    return {
        "incident_id": (
            "provider-service"
        ),
        "severity": "CRITICAL",
        "risk_score": 99.0,
        "dedup_key": (
            "notification:"
            "provider-service:"
            "state"
        ),
        "channels": [
            "telegram"
        ],
    }


def provider_incident():

    return {
        "id": (
            "provider-service"
        ),
        "ip": (
            "192.168.20.130"
        ),
        "alerts": [],
        "response_actions": [],
    }


def test_service_persists_adapter_provider_retry_boundary(
    tmp_path,
):

    clock = Clock(
        datetime(
            2026,
            9,
            22,
            15,
            0,
            tzinfo=timezone.utc,
        )
    )

    repository = (
        NotificationDeliveryRepository(
            make_db(
                tmp_path,
                "service-provider.db",
            ),
            retry_base_seconds=30,
            retry_max_seconds=900,
            now_provider=clock,
        )
    )

    adapter = (
        ProviderRateLimitedAdapter(
            retry_after_seconds=60
        )
    )

    service = NotificationService(
        adapters={
            "telegram": adapter,
        },
        delivery_repository=(
            repository
        ),
    )

    plan = provider_plan()

    result = service.dispatch(
        plan,
        provider_incident(),
    )

    assert result == [
        {
            "channel": "telegram",
            "status": "RATE_LIMITED",
            "backend": (
                "telegram_bot_api"
            ),
            "http_status": 429,
            "reason": (
                "Telegram delivery "
                "rate limited"
            ),
            "retry_after_seconds": 60,
        }
    ]

    assert adapter.calls == 1

    row = repository.get(
        plan[
            "dedup_key"
        ],
        "telegram",
    )

    assert (
        row["status"]
        == "RATE_LIMITED"
    )

    assert row[
        "provider_retry_at"
    ] == datetime(
        2026,
        9,
        22,
        15,
        1,
        tzinfo=timezone.utc,
    ).isoformat(
        timespec="microseconds"
    )

    assert (
        row["last_error"]
        == (
            "Telegram delivery "
            "rate limited"
        )
    )

    serialized = str(
        row
    )

    assert (
        "telegram_bot_api"
        not in serialized
    )

    assert (
        "429"
        not in serialized
    )


def test_service_defers_until_provider_boundary_then_retries(
    tmp_path,
):

    clock = Clock(
        datetime(
            2026,
            9,
            22,
            16,
            0,
            tzinfo=timezone.utc,
        )
    )

    repository = (
        NotificationDeliveryRepository(
            make_db(
                tmp_path,
                "service-boundary.db",
            ),
            retry_base_seconds=30,
            retry_max_seconds=900,
            now_provider=clock,
        )
    )

    adapter = (
        ProviderRateLimitedAdapter(
            retry_after_seconds=60
        )
    )

    service = NotificationService(
        adapters={
            "telegram": adapter,
        },
        delivery_repository=(
            repository
        ),
    )

    plan = provider_plan()
    incident = provider_incident()

    # ----------------------------------------
    # t = 0
    #
    # Provider is contacted and returns 429.
    # ----------------------------------------

    first = service.dispatch(
        plan,
        incident,
    )

    assert (
        first[0]["status"]
        == "RATE_LIMITED"
    )

    assert adapter.calls == 1

    row = repository.get(
        plan[
            "dedup_key"
        ],
        "telegram",
    )

    assert (
        row[
            "attempt_count"
        ]
        == 1
    )

    # ----------------------------------------
    # t = 30
    #
    # Legacy local backoff would already permit
    # a retry here, but provider_retry_at=60
    # must take precedence.
    # ----------------------------------------

    clock.advance(
        30
    )

    second = service.dispatch(
        plan,
        incident,
    )

    assert second == [
        {
            "channel": "telegram",
            "status": "DEFERRED",
            "reason": (
                "Provider retry "
                "boundary active"
            ),
            "retry_at": datetime(
                2026,
                9,
                22,
                16,
                1,
                tzinfo=timezone.utc,
            ).isoformat(
                timespec="microseconds"
            ),
            "attempt_count": 1,
        }
    ]

    # Adapter must NOT have been called.
    assert adapter.calls == 1

    row = repository.get(
        plan[
            "dedup_key"
        ],
        "telegram",
    )

    assert (
        row[
            "attempt_count"
        ]
        == 1
    )

    # ----------------------------------------
    # t = 60 exact boundary
    #
    # Retry is allowed exactly here.
    # ----------------------------------------

    clock.advance(
        30
    )

    third = service.dispatch(
        plan,
        incident,
    )

    assert (
        third[0]["status"]
        == "RATE_LIMITED"
    )

    assert adapter.calls == 2

    row = repository.get(
        plan[
            "dedup_key"
        ],
        "telegram",
    )

    assert (
        row[
            "attempt_count"
        ]
        == 2
    )

    # The second provider 429 installs a NEW
    # provider boundary relative to t=60.
    assert row[
        "provider_retry_at"
    ] == datetime(
        2026,
        9,
        22,
        16,
        2,
        tzinfo=timezone.utc,
    ).isoformat(
        timespec="microseconds"
    )
