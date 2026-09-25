import json
import sqlite3

from engine.storage.repositories.incident_repository import (
    IncidentRepository,
)


class SQLiteTestDB:

    def __init__(
        self,
        path,
    ):
        self.path = str(
            path
        )

    def connect(self):
        connection = sqlite3.connect(
            self.path
        )

        connection.row_factory = (
            sqlite3.Row
        )

        return connection


def create_repository(
    tmp_path,
):
    db = SQLiteTestDB(
        tmp_path / "incidents.db"
    )

    with db.connect() as conn:
        conn.execute(
            """
            CREATE TABLE incidents (
                id TEXT PRIMARY KEY,
                severity TEXT,
                created_at TEXT,
                data_json TEXT NOT NULL
            )
            """
        )

    return (
        IncidentRepository(
            db
        ),
        db,
    )


def insert_incident(
    db,
    incident_id,
    severity,
    created_at,
):
    payload = {
        "id": incident_id,
        "severity": severity,
        "created": created_at,
    }

    with db.connect() as conn:
        conn.execute(
            """
            INSERT INTO incidents (
                id,
                severity,
                created_at,
                data_json
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                incident_id,
                severity,
                created_at,
                json.dumps(
                    payload
                ),
            ),
        )


def seed_incidents(
    db,
):
    values = (
        (
            "INC-001",
            "LOW",
            "2026-09-24T10:00:00",
        ),
        (
            "INC-002",
            "HIGH",
            "2026-09-24T11:00:00",
        ),
        (
            "INC-003",
            "CRITICAL",
            "2026-09-24T12:00:00",
        ),
        (
            "INC-004",
            "HIGH",
            "2026-09-24T13:00:00",
        ),
        (
            "INC-005",
            "MEDIUM",
            "2026-09-24T14:00:00",
        ),
    )

    for (
        incident_id,
        severity,
        created_at,
    ) in values:
        insert_incident(
            db,
            incident_id,
            severity,
            created_at,
        )


def test_list_recent_is_bounded_and_newest_first(
    tmp_path,
):
    repository, db = (
        create_repository(
            tmp_path
        )
    )

    seed_incidents(
        db
    )

    incidents = (
        repository.list_recent(
            limit=3
        )
    )

    assert [
        incident["id"]
        for incident in incidents
    ] == [
        "INC-005",
        "INC-004",
        "INC-003",
    ]


def test_list_recent_by_severity_filters_in_sql(
    tmp_path,
):
    repository, db = (
        create_repository(
            tmp_path
        )
    )

    seed_incidents(
        db
    )

    incidents = (
        repository
        .list_recent_by_severity(
            "high",
            limit=10,
        )
    )

    assert [
        incident["id"]
        for incident in incidents
    ] == [
        "INC-004",
        "INC-002",
    ]


def test_zero_and_negative_limits_return_empty(
    tmp_path,
):
    repository, db = (
        create_repository(
            tmp_path
        )
    )

    seed_incidents(
        db
    )

    assert (
        repository.list_recent(
            limit=0
        )
        == []
    )

    assert (
        repository.list_recent(
            limit=-1
        )
        == []
    )

    assert (
        repository
        .list_recent_by_severity(
            "HIGH",
            limit=0,
        )
        == []
    )


def test_invalid_limit_uses_safe_default(
    tmp_path,
):
    repository, db = (
        create_repository(
            tmp_path
        )
    )

    for index in range(30):
        insert_incident(
            db,
            f"INC-{index:03d}",
            "LOW",
            (
                "2026-09-24T"
                f"{index % 24:02d}:"
                f"{index % 60:02d}:00"
            ),
        )

    incidents = (
        repository.list_recent(
            limit="invalid"
        )
    )

    assert len(incidents) == (
        repository.DEFAULT_QUERY_LIMIT
    )


def test_query_limit_is_hard_capped(
    tmp_path,
):
    repository, db = (
        create_repository(
            tmp_path
        )
    )

    for index in range(150):
        insert_incident(
            db,
            f"INC-{index:03d}",
            "LOW",
            (
                "2026-09-24T"
                f"{index % 24:02d}:"
                f"{index % 60:02d}:00"
            ),
        )

    incidents = (
        repository.list_recent(
            limit=999999
        )
    )

    assert len(incidents) == (
        repository.MAX_QUERY_LIMIT
    )


def test_severity_query_limit_is_hard_capped(
    tmp_path,
):
    repository, db = (
        create_repository(
            tmp_path
        )
    )

    for index in range(150):
        insert_incident(
            db,
            f"INC-{index:03d}",
            "HIGH",
            (
                "2026-09-24T"
                f"{index % 24:02d}:"
                f"{index % 60:02d}:00"
            ),
        )

    incidents = (
        repository
        .list_recent_by_severity(
            "HIGH",
            limit=999999,
        )
    )

    assert len(incidents) == (
        repository.MAX_QUERY_LIMIT
    )


def test_empty_severity_returns_empty(
    tmp_path,
):
    repository, db = (
        create_repository(
            tmp_path
        )
    )

    seed_incidents(
        db
    )

    assert (
        repository
        .list_recent_by_severity(
            "",
            limit=10,
        )
        == []
    )

    assert (
        repository
        .list_recent_by_severity(
            None,
            limit=10,
        )
        == []
    )


def test_query_results_are_detached_json_objects(
    tmp_path,
):
    repository, db = (
        create_repository(
            tmp_path
        )
    )

    seed_incidents(
        db
    )

    first = (
        repository.list_recent(
            limit=1
        )
    )

    first[0][
        "severity"
    ] = "LOW"

    second = (
        repository.list_recent(
            limit=1
        )
    )

    assert (
        second[0]["severity"]
        == "MEDIUM"
    )
