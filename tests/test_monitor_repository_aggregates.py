import json
import sqlite3

from engine.storage.repositories.campaign_repository import (
    CampaignRepository,
)
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


def build_db(
    tmp_path,
):
    db = SQLiteTestDB(
        tmp_path / "monitor.db"
    )

    with db.connect() as conn:

        conn.execute(
            """
            CREATE TABLE incidents (
                id TEXT PRIMARY KEY,
                severity TEXT,
                risk_score INTEGER,
                created_at TEXT,
                data_json TEXT NOT NULL
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE campaigns (
                id TEXT PRIMARY KEY,
                risk,
                created_at TEXT,
                data_json TEXT NOT NULL
            )
            """
        )

    return db


def insert_incident(
    db,
    incident_id,
    severity,
    risk_score,
):
    payload = {
        "id": incident_id,
        "severity": severity,
        "risk_score": risk_score,
    }

    with db.connect() as conn:

        conn.execute(
            """
            INSERT INTO incidents (
                id,
                severity,
                risk_score,
                created_at,
                data_json
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                incident_id,
                severity,
                risk_score,
                "2026-09-25T00:00:00",
                json.dumps(
                    payload
                ),
            ),
        )


def insert_campaign(
    db,
    campaign_id,
    risk,
):
    payload = {
        "id": campaign_id,
        "risk": risk,
    }

    with db.connect() as conn:

        conn.execute(
            """
            INSERT INTO campaigns (
                id,
                risk,
                created_at,
                data_json
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                campaign_id,
                risk,
                "2026-09-25T00:00:00",
                json.dumps(
                    payload
                ),
            ),
        )


def test_incident_summary_is_exact(
    tmp_path,
):
    db = build_db(
        tmp_path
    )

    repository = IncidentRepository(
        db
    )

    values = (
        (
            "INC-001",
            "LOW",
            10,
        ),
        (
            "INC-002",
            "MEDIUM",
            30,
        ),
        (
            "INC-003",
            "HIGH",
            70,
        ),
        (
            "INC-004",
            "CRITICAL",
            95,
        ),
        (
            "INC-005",
            "high",
            80,
        ),
    )

    for value in values:
        insert_incident(
            db,
            *value,
        )

    assert (
        repository.summary_stats()
        == {
            "incidents": 5,
            "high_critical": 3,
        }
    )


def test_incident_summary_empty_database(
    tmp_path,
):
    db = build_db(
        tmp_path
    )

    repository = IncidentRepository(
        db
    )

    assert (
        repository.summary_stats()
        == {
            "incidents": 0,
            "high_critical": 0,
        }
    )


def test_campaign_summary_is_exact(
    tmp_path,
):
    db = build_db(
        tmp_path
    )

    repository = CampaignRepository(
        db
    )

    insert_campaign(
        db,
        "CAM-001",
        20,
    )

    insert_campaign(
        db,
        "CAM-002",
        87.5,
    )

    insert_campaign(
        db,
        "CAM-003",
        41,
    )

    assert (
        repository.summary_stats()
        == {
            "campaigns": 3,
            "max_risk": 87.5,
        }
    )


def test_campaign_summary_empty_database(
    tmp_path,
):
    db = build_db(
        tmp_path
    )

    repository = CampaignRepository(
        db
    )

    assert (
        repository.summary_stats()
        == {
            "campaigns": 0,
            "max_risk": 0.0,
        }
    )


def test_campaign_summary_tolerates_text_numeric_risk(
    tmp_path,
):
    db = build_db(
        tmp_path
    )

    repository = CampaignRepository(
        db
    )

    insert_campaign(
        db,
        "CAM-001",
        "73.25",
    )

    insert_campaign(
        db,
        "CAM-002",
        "12",
    )

    assert (
        repository.summary_stats()
        == {
            "campaigns": 2,
            "max_risk": 73.25,
        }
    )


def test_aggregate_queries_do_not_deserialize_json(
    tmp_path,
):
    db = build_db(
        tmp_path
    )

    with db.connect() as conn:

        conn.execute(
            """
            INSERT INTO incidents (
                id,
                severity,
                risk_score,
                created_at,
                data_json
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                "INC-BROKEN",
                "CRITICAL",
                99,
                "2026-09-25T00:00:00",
                "{not valid json",
            ),
        )

        conn.execute(
            """
            INSERT INTO campaigns (
                id,
                risk,
                created_at,
                data_json
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                "CAM-BROKEN",
                91,
                "2026-09-25T00:00:00",
                "{not valid json",
            ),
        )

    incident_repository = (
        IncidentRepository(
            db
        )
    )

    campaign_repository = (
        CampaignRepository(
            db
        )
    )

    assert (
        incident_repository
        .summary_stats()
        == {
            "incidents": 1,
            "high_critical": 1,
        }
    )

    assert (
        campaign_repository
        .summary_stats()
        == {
            "campaigns": 1,
            "max_risk": 91.0,
        }
    )
