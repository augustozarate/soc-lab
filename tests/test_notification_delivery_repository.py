from engine.bootstrap.builders.repository_builder import (
    build_repositories,
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


def repository(
    tmp_path,
):

    db = Database(
        str(
            tmp_path
            / "notification.db"
        )
    )

    MigrationRunner(
        db
    ).run()

    return (
        NotificationDeliveryRepository(
            db
        ),
        db,
    )


def test_migration_creates_notification_delivery_table(
    tmp_path,
):

    repo, db = repository(
        tmp_path
    )

    assert repo is not None

    with db.connect() as conn:

        row = conn.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name = 'notification_deliveries'
            """
        ).fetchone()

    assert row is not None


def test_first_claim_creates_pending_delivery(
    tmp_path,
):

    repo, _ = repository(
        tmp_path
    )

    assert repo.claim(
        dedup_key="notification:a",
        channel="local",
        incident_id="incident-a",
        severity="HIGH",
    )

    row = repo.get(
        "notification:a",
        "local",
    )

    assert row[
        "status"
    ] == "PENDING"

    assert row[
        "attempt_count"
    ] == 1

    assert row[
        "incident_id"
    ] == "incident-a"


def test_success_suppresses_same_channel(
    tmp_path,
):

    repo, _ = repository(
        tmp_path
    )

    assert repo.claim(
        "notification:a",
        "local",
    )

    assert repo.mark_success(
        "notification:a",
        "local",
        backend="console",
    )

    assert not repo.claim(
        "notification:a",
        "local",
    )

    row = repo.get(
        "notification:a",
        "local",
    )

    assert row[
        "status"
    ] == "SUCCESS"

    assert row[
        "attempt_count"
    ] == 1


def test_dedup_is_independent_per_channel(
    tmp_path,
):

    repo, _ = repository(
        tmp_path
    )

    assert repo.claim(
        "notification:a",
        "local",
    )

    assert repo.mark_success(
        "notification:a",
        "local",
    )

    assert repo.claim(
        "notification:a",
        "email",
    )


def test_failed_delivery_is_retryable(
    tmp_path,
):

    repo, _ = repository(
        tmp_path
    )

    assert repo.claim(
        "notification:a",
        "email",
    )

    assert repo.mark_failed(
        "notification:a",
        "email",
        "smtp unavailable",
        backend="smtp",
    )

    assert repo.claim(
        "notification:a",
        "email",
    )

    row = repo.get(
        "notification:a",
        "email",
    )

    assert row[
        "status"
    ] == "PENDING"

    assert row[
        "attempt_count"
    ] == 2

    assert row[
        "last_error"
    ] is None


def test_skipped_delivery_is_retryable(
    tmp_path,
):

    repo, _ = repository(
        tmp_path
    )

    assert repo.claim(
        "notification:a",
        "telegram",
    )

    assert repo.mark_skipped(
        "notification:a",
        "telegram",
        "adapter missing",
    )

    assert repo.claim(
        "notification:a",
        "telegram",
    )

    assert repo.get(
        "notification:a",
        "telegram",
    )[
        "attempt_count"
    ] == 2


def test_pending_delivery_cannot_be_claimed_twice(
    tmp_path,
):

    repo, _ = repository(
        tmp_path
    )

    assert repo.claim(
        "notification:a",
        "local",
    )

    assert not repo.claim(
        "notification:a",
        "local",
    )


def test_reset_incomplete_makes_pending_retryable(
    tmp_path,
):

    repo, _ = repository(
        tmp_path
    )

    assert repo.claim(
        "notification:a",
        "local",
    )

    changed = (
        repo.reset_incomplete()
    )

    assert changed == 1

    row = repo.get(
        "notification:a",
        "local",
    )

    assert row[
        "status"
    ] == "FAILED"

    assert (
        "Recovered incomplete delivery"
        in row["last_error"]
    )

    assert repo.claim(
        "notification:a",
        "local",
    )


def test_list_for_incident_returns_channel_rows(
    tmp_path,
):

    repo, _ = repository(
        tmp_path
    )

    for channel in (
        "local",
        "email",
    ):

        assert repo.claim(
            dedup_key="notification:a",
            channel=channel,
            incident_id="incident-a",
            severity="HIGH",
        )

    rows = repo.list_for_incident(
        "incident-a"
    )

    assert {
        row["channel"]
        for row in rows
    } == {
        "local",
        "email",
    }


def test_repository_builder_exposes_delivery_repository(
    tmp_path,
):

    class Container:
        pass

    container = Container()

    build_repositories(
        container,
        str(
            tmp_path
            / "builder.db"
        ),
    )

    assert isinstance(
        container
        .notification_delivery_repository,
        NotificationDeliveryRepository,
    )
