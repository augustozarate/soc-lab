import json


class IncidentRepository:

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

    def list_all(self):

        with self.db.connect() as conn:

            rows = conn.execute(
                """
                SELECT data_json
                FROM incidents
                ORDER BY created_at DESC
                """
            ).fetchall()

        return [
            json.loads(row["data_json"])
            for row in rows
        ]