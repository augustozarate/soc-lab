from datetime import (
    datetime,
    timedelta,
    timezone,
)

import pytest

from engine.bootstrap.builders.repository_builder import (
    build_repositories,
)
from engine.storage.repositories.response_block_repository import (
    ResponseBlockRepository,
)
from engine.storage.sqlite.database import (
    Database,
)
from engine.storage.sqlite.migrations import (
    MigrationRunner,
)


TARGET = "192.168.20.130"


@pytest.fixture
def repository(
    tmp_path,
):

    db = Database(
        str(
            tmp_path
            / "soc.db"
        )
    )

    MigrationRunner(
        db
    ).run()

    return ResponseBlockRepository(
        db
    )


def utc(
    year,
    month,
    day,
    hour=0,
    minute=0,
    second=0,
):

    return datetime(
        year,
        month,
        day,
        hour,
        minute,
        second,
        tzinfo=timezone.utc,
    )


def test_migration_creates_response_blocks_table(
    tmp_path,
):

    db = Database(
        str(
            tmp_path
            / "soc.db"
        )
    )

    runner = MigrationRunner(
        db
    )

    runner.run()
    runner.run()

    with db.connect() as conn:

        row = conn.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name = 'response_blocks'
            """
        ).fetchone()

    assert row is not None


def test_upsert_active_creates_durable_block(
    repository,
):

    expires_at = utc(
        2026,
        9,
        21,
        4,
        0,
    )

    result = repository.upsert_active(
        target=TARGET,
        expires_at=expires_at,
        execution_mode="ENFORCED",
        backend="windows_firewall",
        rule_name=(
            "SOC-LAB-BLOCK-192-168-20-130"
        ),
        source_incident_id="incident-1",
    )

    assert result["target"] == TARGET
    assert (
        result["desired_state"]
        == "BLOCKED"
    )
    assert result["status"] == "ACTIVE"
    assert (
        result["execution_mode"]
        == "ENFORCED"
    )
    assert (
        result["backend"]
        == "windows_firewall"
    )
    assert (
        result["source_incident_id"]
        == "incident-1"
    )
    assert result["last_error"] is None

    stored_expiry = datetime.fromisoformat(
        result["expires_at"]
    )

    assert stored_expiry.tzinfo is not None
    assert (
        stored_expiry.utcoffset()
        == timedelta(0)
    )


def test_get_missing_returns_none(
    repository,
):

    assert (
        repository.get(
            TARGET
        )
        is None
    )


def test_upsert_preserves_created_at_and_resets_lifecycle(
    repository,
):

    first_expiry = utc(
        2026,
        9,
        21,
        4,
        0,
    )

    repository.upsert_active(
        target=TARGET,
        expires_at=first_expiry,
        execution_mode="ENFORCED",
        backend="windows_firewall",
    )

    first = repository.get(
        TARGET
    )

    repository.mark_failed(
        TARGET,
        "test failure",
        utc(
            2026,
            9,
            21,
            3,
            30,
        ),
    )

    second_expiry = utc(
        2026,
        9,
        21,
        5,
        0,
    )

    repository.upsert_active(
        target=TARGET,
        expires_at=second_expiry,
        execution_mode="SIMULATED",
        backend="memory",
        source_incident_id="incident-2",
    )

    second = repository.get(
        TARGET
    )

    assert (
        second["created_at"]
        == first["created_at"]
    )
    assert second["status"] == "ACTIVE"
    assert (
        second["desired_state"]
        == "BLOCKED"
    )
    assert second["last_error"] is None
    assert (
        second["execution_mode"]
        == "SIMULATED"
    )
    assert second["backend"] == "memory"
    assert (
        second["source_incident_id"]
        == "incident-2"
    )


def test_list_active_only_returns_active_rows(
    repository,
):

    repository.upsert_active(
        target="192.168.20.130",
        expires_at=utc(
            2026,
            9,
            21,
            4,
            0,
        ),
        execution_mode="ENFORCED",
        backend="windows_firewall",
    )

    repository.upsert_active(
        target="192.168.20.131",
        expires_at=utc(
            2026,
            9,
            21,
            5,
            0,
        ),
        execution_mode="ENFORCED",
        backend="windows_firewall",
    )

    repository.mark_released(
        "192.168.20.131",
        utc(
            2026,
            9,
            21,
            3,
            0,
        ),
    )

    active = repository.list_active()

    assert [
        row["target"]
        for row in active
    ] == [
        "192.168.20.130"
    ]


def test_list_expired_is_query_only(
    repository,
):

    repository.upsert_active(
        target="192.168.20.130",
        expires_at=utc(
            2026,
            9,
            21,
            3,
            0,
        ),
        execution_mode="ENFORCED",
        backend="windows_firewall",
    )

    repository.upsert_active(
        target="192.168.20.131",
        expires_at=utc(
            2026,
            9,
            21,
            5,
            0,
        ),
        execution_mode="ENFORCED",
        backend="windows_firewall",
    )

    expired = repository.list_expired(
        utc(
            2026,
            9,
            21,
            4,
            0,
        )
    )

    assert [
        row["target"]
        for row in expired
    ] == [
        "192.168.20.130"
    ]

    still_active = repository.get(
        "192.168.20.130"
    )

    assert (
        still_active["status"]
        == "ACTIVE"
    )
    assert (
        still_active["desired_state"]
        == "BLOCKED"
    )


def test_mark_expired_transitions_desired_state(
    repository,
):

    repository.upsert_active(
        target=TARGET,
        expires_at=utc(
            2026,
            9,
            21,
            3,
            0,
        ),
        execution_mode="ENFORCED",
        backend="windows_firewall",
    )

    changed = repository.mark_expired(
        TARGET,
        utc(
            2026,
            9,
            21,
            3,
            1,
        ),
    )

    assert changed is True

    result = repository.get(
        TARGET
    )

    assert result["status"] == "EXPIRED"
    assert (
        result["desired_state"]
        == "UNBLOCKED"
    )

    assert (
        repository.mark_expired(
            TARGET,
            utc(
                2026,
                9,
                21,
                3,
                2,
            ),
        )
        is False
    )


def test_mark_released_is_idempotent(
    repository,
):

    repository.upsert_active(
        target=TARGET,
        expires_at=utc(
            2026,
            9,
            21,
            3,
            0,
        ),
        execution_mode="ENFORCED",
        backend="windows_firewall",
    )

    repository.mark_expired(
        TARGET,
        utc(
            2026,
            9,
            21,
            3,
            1,
        ),
    )

    assert (
        repository.mark_released(
            TARGET,
            utc(
                2026,
                9,
                21,
                3,
                2,
            ),
        )
        is True
    )

    result = repository.get(
        TARGET
    )

    assert result["status"] == "RELEASED"
    assert (
        result["desired_state"]
        == "UNBLOCKED"
    )
    assert result["last_error"] is None

    assert (
        repository.mark_released(
            TARGET,
            utc(
                2026,
                9,
                21,
                3,
                3,
            ),
        )
        is False
    )


def test_mark_failed_preserves_desired_state(
    repository,
):

    repository.upsert_active(
        target=TARGET,
        expires_at=utc(
            2026,
            9,
            21,
            4,
            0,
        ),
        execution_mode="ENFORCED",
        backend="windows_firewall",
    )

    changed = repository.mark_failed(
        TARGET,
        "backend unavailable",
        utc(
            2026,
            9,
            21,
            3,
            0,
        ),
    )

    assert changed is True

    result = repository.get(
        TARGET
    )

    assert result["status"] == "FAILED"
    assert (
        result["desired_state"]
        == "BLOCKED"
    )
    assert (
        result["last_error"]
        == "backend unavailable"
    )


@pytest.mark.parametrize(
    "operation",
    [
        "upsert",
        "expired",
        "released",
        "failed",
    ],
)
def test_naive_datetimes_are_rejected(
    repository,
    operation,
):

    naive = datetime(
        2026,
        9,
        21,
        3,
        0,
    )

    if operation == "upsert":

        with pytest.raises(
            ValueError,
            match="timezone-aware",
        ):

            repository.upsert_active(
                target=TARGET,
                expires_at=naive,
                execution_mode="ENFORCED",
                backend="windows_firewall",
            )

        return

    repository.upsert_active(
        target=TARGET,
        expires_at=utc(
            2026,
            9,
            21,
            4,
            0,
        ),
        execution_mode="ENFORCED",
        backend="windows_firewall",
    )

    if operation == "expired":

        with pytest.raises(
            ValueError,
            match="timezone-aware",
        ):

            repository.mark_expired(
                TARGET,
                naive,
            )

    elif operation == "released":

        with pytest.raises(
            ValueError,
            match="timezone-aware",
        ):

            repository.mark_released(
                TARGET,
                naive,
            )

    else:

        with pytest.raises(
            ValueError,
            match="timezone-aware",
        ):

            repository.mark_failed(
                TARGET,
                "error",
                naive,
            )


def test_repository_builder_exposes_response_block_repository(
    tmp_path,
):

    class Container:
        pass

    container = Container()

    build_repositories(
        container,
        str(
            tmp_path
            / "soc.db"
        ),
    )

    assert isinstance(
        container.response_block_repository,
        ResponseBlockRepository,
    )

    with container.database.connect() as conn:

        row = conn.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name = 'response_blocks'
            """
        ).fetchone()

    assert row is not None
