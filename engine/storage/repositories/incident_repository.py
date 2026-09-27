import json


class IncidentRepository:

    DEFAULT_QUERY_LIMIT = 20
    MAX_QUERY_LIMIT = 100

    def __init__(self, db):
        self.db = db

    def save(self, incident):

        payload = json.dumps(
            incident,
            default=str,
            ensure_ascii=False
        )

        with self.db.connect() as conn:

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

                ON CONFLICT(id) DO UPDATE SET

                    ip = excluded.ip,
                    severity = excluded.severity,
                    status = excluded.status,
                    risk_score = excluded.risk_score,
                    campaign_id = excluded.campaign_id,
                    updated_at = excluded.updated_at,
                    last_seen = excluded.last_seen,
                    data_json = excluded.data_json
                """,
                (
                    incident.get("id"),
                    incident.get("ip"),
                    incident.get("severity"),
                    incident.get("status"),
                    incident.get("risk_score", 0),
                    incident.get("campaign_id"),
                    incident.get("created"),
                    incident.get("updated"),
                    incident.get("last_seen"),
                    payload
                )
            )

    def get(self, incident_id):

        with self.db.connect() as conn:

            row = conn.execute(
                """
                SELECT data_json
                FROM incidents
                WHERE id = ?
                """,
                (incident_id,)
            ).fetchone()

        if not row:
            return None

        return json.loads(
            row["data_json"]
        )

    def list_recent(
        self,
        limit=DEFAULT_QUERY_LIMIT,
    ):
        bounded_limit = self._bounded_limit(
            limit
        )

        if bounded_limit == 0:
            return []

        with self.db.connect() as conn:

            rows = conn.execute(
                """
                SELECT data_json
                FROM incidents
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (
                    bounded_limit,
                ),
            ).fetchall()

        return [
            json.loads(
                row["data_json"]
            )
            for row in rows
        ]

    def list_recent_by_severity(
        self,
        severity,
        limit=DEFAULT_QUERY_LIMIT,
    ):
        bounded_limit = self._bounded_limit(
            limit
        )

        normalized_severity = (
            ""
            if severity is None
            else str(
                severity
            ).strip().upper()
        )

        if (
            bounded_limit == 0
            or not normalized_severity
        ):
            return []

        with self.db.connect() as conn:

            rows = conn.execute(
                """
                SELECT data_json
                FROM incidents
                WHERE UPPER(severity) = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (
                    normalized_severity,
                    bounded_limit,
                ),
            ).fetchall()

        return [
            json.loads(
                row["data_json"]
            )
            for row in rows
        ]

    @classmethod
    def _bounded_limit(
        cls,
        limit,
    ):
        try:
            normalized = int(
                limit
            )

        except (
            TypeError,
            ValueError,
        ):
            normalized = (
                cls.DEFAULT_QUERY_LIMIT
            )

        if normalized <= 0:
            return 0

        return min(
            normalized,
            cls.MAX_QUERY_LIMIT,
        )

    def summary_stats(self):

        with self.db.connect() as conn:

            row = conn.execute(
                """
                SELECT
                    COUNT(*) AS incidents,
                    COALESCE(
                        SUM(
                            CASE
                                WHEN UPPER(severity)
                                    IN ('HIGH', 'CRITICAL')
                                THEN 1
                                ELSE 0
                            END
                        ),
                        0
                    ) AS high_critical,
                    COALESCE(
                        MAX(
                            CAST(
                                risk_score AS REAL
                            )
                        ),
                        0
                    ) AS max_incident_risk,
                    COALESCE(
                        SUM(
                            CASE
                                WHEN EXISTS (
                                    SELECT 1
                                    FROM json_each(
                                        CASE
                                            WHEN json_valid(
                                                incidents.data_json
                                            )
                                            THEN incidents.data_json
                                            ELSE '{"alerts":[]}'
                                        END,
                                        '$.alerts'
                                    ) AS alert
                                    WHERE
                                        json_extract(
                                            alert.value,
                                            '$.type'
                                        ) = 'UEBA_BRUTE_FORCE'
                                        OR json_extract(
                                            alert.value,
                                            '$.rule_id'
                                        ) = 'UEBA_BRUTE_FORCE'
                                )
                                THEN 1
                                ELSE 0
                            END
                        ),
                        0
                    ) AS ueba_incidents
                FROM incidents
                """
            ).fetchone()

        if not row:
            return {
                "incidents": 0,
                "high_critical": 0,
                "max_incident_risk": 0.0,
                "ueba_incidents": 0,
            }

        return {
            "incidents": int(
                row["incidents"]
                or 0
            ),
            "high_critical": int(
                row["high_critical"]
                or 0
            ),
            "max_incident_risk": float(
                row["max_incident_risk"]
                or 0
            ),
            "ueba_incidents": int(
                row["ueba_incidents"]
                or 0
            ),
        }

    def list_recent_summaries(
        self,
        limit=DEFAULT_QUERY_LIMIT,
    ):
        bounded_limit = self._bounded_limit(
            limit
        )

        if bounded_limit == 0:
            return []

        with self.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    id,
                    severity
                FROM incidents
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (
                    bounded_limit,
                ),
            ).fetchall()

        return [
            {
                "id": row["id"],
                "severity": row["severity"],
            }
            for row in rows
        ]
