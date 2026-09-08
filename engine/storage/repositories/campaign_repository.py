import json
from datetime import datetime


class CampaignRepository:

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