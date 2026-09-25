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

        with self.connect() as conn:
            conn.execute(
                """
                CREATE TABLE incidents (
                    id TEXT PRIMARY KEY,
                    ip TEXT,
                    severity TEXT,
                    status TEXT,
                    risk_score REAL,
                    campaign_id TEXT,
                    created_at TEXT,
                    updated_at TEXT,
                    last_seen TEXT,
                    data_json TEXT
                )
                """
            )

    def connect(self):
        connection = sqlite3.connect(
            self.path
        )

        connection.row_factory = (
            sqlite3.Row
        )

        return connection


def build_repository(
    tmp_path,
):
    db = SQLiteTestDB(
        tmp_path / "projection.db"
    )

    return (
        IncidentRepository(
            db
        ),
        db,
    )


def insert_incident(
    db,
    *,
    incident_id,
    severity,
    created_at,
    ip="192.0.2.10",
    data_json='{"internal_note":"PRIVATE"}',
):
    with db.connect() as conn:
        conn.execute(
            """
            INSERT INTO incidents (
                id,
                ip,
                severity,
                status,
                risk_score,
                campaign_id,
                created_at,
                updated_at,
                last_seen,
                data_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident_id,
                ip,
                severity,
                "OPEN",
                90.0,
                None,
                created_at,
                created_at,
                created_at,
                data_json,
            ),
        )


def test_recent_summaries_returns_only_id_and_severity(
    tmp_path,
):
    repository, db = build_repository(
        tmp_path
    )

    insert_incident(
        db,
        incident_id="INC-001",
        severity="CRITICAL",
        created_at="2026-09-25T10:00:00Z",
    )

    rows = (
        repository
        .list_recent_summaries(
            limit=10
        )
    )

    assert rows == [
        {
            "id": "INC-001",
            "severity": "CRITICAL",
        },
    ]

    assert set(
        rows[0]
    ) == {
        "id",
        "severity",
    }


def test_recent_summaries_are_ordered_newest_first(
    tmp_path,
):
    repository, db = build_repository(
        tmp_path
    )

    insert_incident(
        db,
        incident_id="INC-OLD",
        severity="LOW",
        created_at="2026-09-25T10:00:00Z",
    )

    insert_incident(
        db,
        incident_id="INC-NEW",
        severity="HIGH",
        created_at="2026-09-25T11:00:00Z",
    )

    rows = (
        repository
        .list_recent_summaries(
            limit=10
        )
    )

    assert [
        row["id"]
        for row in rows
    ] == [
        "INC-NEW",
        "INC-OLD",
    ]


def test_recent_summaries_respects_limit(
    tmp_path,
):
    repository, db = build_repository(
        tmp_path
    )

    for index in range(
        5
    ):
        insert_incident(
            db,
            incident_id=(
                f"INC-{index}"
            ),
            severity="LOW",
            created_at=(
                "2026-09-25T"
                f"10:0{index}:00Z"
            ),
        )

    rows = (
        repository
        .list_recent_summaries(
            limit=2
        )
    )

    assert len(
        rows
    ) == 2


def test_recent_summaries_zero_limit_returns_empty(
    tmp_path,
):
    repository, db = build_repository(
        tmp_path
    )

    insert_incident(
        db,
        incident_id="INC-001",
        severity="HIGH",
        created_at="2026-09-25T10:00:00Z",
    )

    assert (
        repository
        .list_recent_summaries(
            limit=0
        )
        == []
    )


def test_recent_summaries_hard_caps_limit(
    tmp_path,
):
    repository, db = build_repository(
        tmp_path
    )

    for index in range(
        105
    ):
        insert_incident(
            db,
            incident_id=(
                f"INC-{index:03d}"
            ),
            severity="LOW",
            created_at=(
                "2026-09-25T"
                f"10:{index // 60:02d}:"
                f"{index % 60:02d}Z"
            ),
        )

    rows = (
        repository
        .list_recent_summaries(
            limit=9999
        )
    )

    assert len(
        rows
    ) == 100


def test_recent_summaries_invalid_limit_uses_safe_default(
    tmp_path,
):
    repository, db = build_repository(
        tmp_path
    )

    for index in range(
        25
    ):
        insert_incident(
            db,
            incident_id=(
                f"INC-{index:03d}"
            ),
            severity="LOW",
            created_at=(
                "2026-09-25T"
                f"10:{index:02d}:00Z"
            ),
        )

    rows = (
        repository
        .list_recent_summaries(
            limit="invalid"
        )
    )

    assert len(
        rows
    ) == 20


def test_recent_summaries_does_not_deserialize_data_json(
    tmp_path,
):
    repository, db = build_repository(
        tmp_path
    )

    insert_incident(
        db,
        incident_id="INC-001",
        severity="CRITICAL",
        created_at="2026-09-25T10:00:00Z",
        data_json=(
            "{THIS IS NOT VALID JSON"
        ),
    )

    rows = (
        repository
        .list_recent_summaries(
            limit=10
        )
    )

    assert rows == [
        {
            "id": "INC-001",
            "severity": "CRITICAL",
        },
    ]


def test_recent_summaries_does_not_return_sensitive_columns(
    tmp_path,
):
    repository, db = build_repository(
        tmp_path
    )

    insert_incident(
        db,
        incident_id="INC-001",
        severity="HIGH",
        created_at="2026-09-25T10:00:00Z",
        ip="203.0.113.77",
        data_json=(
            '{"username":"demo-user",'
            '"internal_note":"PRIVATE"}'
        ),
    )

    rows = (
        repository
        .list_recent_summaries(
            limit=10
        )
    )

    serialized = repr(
        rows
    )

    assert (
        "203.0.113.77"
        not in serialized
    )

    assert (
        "demo-user"
        not in serialized
    )

    assert (
        "PRIVATE"
        not in serialized
    )
