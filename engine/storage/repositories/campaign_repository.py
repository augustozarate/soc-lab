import json
from datetime import datetime


class CampaignRepository:

    DEFAULT_QUERY_LIMIT = 20
    MAX_QUERY_LIMIT = 100

    def __init__(self, db):
        self.db = db

    def save(self, campaign):

        payload = json.dumps(
            campaign,
            default=str,
            ensure_ascii=False
        )

        now = datetime.utcnow().isoformat()

        with self.db.connect() as conn:

            conn.execute(
                """
                INSERT INTO campaigns (
                    id,
                    stage,
                    risk,
                    created_at,
                    updated_at,
                    data_json
                )
                VALUES (?, ?, ?, ?, ?, ?)

                ON CONFLICT(id) DO UPDATE SET

                    stage = excluded.stage,
                    risk = excluded.risk,
                    updated_at = excluded.updated_at,
                    data_json = excluded.data_json
                """,
                (
                    campaign.get("id"),
                    campaign.get("stage"),
                    campaign.get("risk", 0),
                    campaign.get("created", now),
                    now,
                    payload
                )
            )

    def get(self, campaign_id):

        with self.db.connect() as conn:

            row = conn.execute(
                """
                SELECT data_json
                FROM campaigns
                WHERE id = ?
                """,
                (campaign_id,)
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
                FROM campaigns
                ORDER BY created_at DESC
                """
            ).fetchall()

        return [
            json.loads(row["data_json"])
            for row in rows
        ]

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
                FROM campaigns
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
                    COUNT(*) AS campaigns,
                    COALESCE(
                        MAX(
                            CAST(
                                risk AS REAL
                            )
                        ),
                        0
                    ) AS max_risk
                FROM campaigns
                """
            ).fetchone()

        if not row:
            return {
                "campaigns": 0,
                "max_risk": 0.0,
            }

        return {
            "campaigns": int(
                row["campaigns"]
                or 0
            ),
            "max_risk": float(
                row["max_risk"]
                or 0
            ),
        }
