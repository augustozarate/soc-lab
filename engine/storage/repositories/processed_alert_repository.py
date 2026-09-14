class ProcessedAlertRepository:

    def __init__(self, db):
        self.db = db

    def build_key(
        self,
        alert
    ):

        source_record_id = alert.get(
            "source_record_id"
        )

        if source_record_id is None:
            return None

        alert_type = (
            alert.get("rule_id")
            or alert.get("type")
        )

        if not alert_type:
            return None

        source_event_id = alert.get(
            "source_event_id"
        )

        ip = alert.get("ip")

        return (
            f"{alert_type}|"
            f"{ip}|"
            f"{source_event_id}|"
            f"{source_record_id}"
        )

    def claim(
        self,
        dedup_key,
        alert_type,
        ip,
        source_record_id,
        source_event_id,
        owner_task_id
    ):

        with self.db.connect() as conn:

            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO processed_alerts (
                    dedup_key,
                    alert_type,
                    ip,
                    source_record_id,
                    source_event_id,
                    status,
                    owner_task_id,
                    claimed_at
                )
                VALUES (
                    ?, ?, ?, ?, ?,
                    'PROCESSING',
                    ?,
                    datetime('now')
                )
                """,
                (
                    dedup_key,
                    alert_type,
                    ip,
                    source_record_id,
                    source_event_id,
                    owner_task_id
                )
            )

            if cursor.rowcount == 1:
                return True

            row = conn.execute(
                """
                SELECT
                    status,
                    owner_task_id
                FROM processed_alerts
                WHERE dedup_key = ?
                """,
                (dedup_key,)
            ).fetchone()

        if not row:
            return False

        if row["status"] == "COMPLETED":
            return False

        if (
            row["status"] == "PROCESSING"
            and row["owner_task_id"]
            == owner_task_id
        ):
            return True

        return False

    def complete(
        self,
        dedup_key,
        owner_task_id
    ):

        with self.db.connect() as conn:

            conn.execute(
                """
                UPDATE processed_alerts
                SET
                    status = 'COMPLETED',
                    completed_at = datetime('now')
                WHERE dedup_key = ?
                AND owner_task_id = ?
                """,
                (
                    dedup_key,
                    owner_task_id
                )
            )

    def release(
        self,
        dedup_key,
        owner_task_id
    ):

        with self.db.connect() as conn:

            conn.execute(
                """
                DELETE FROM processed_alerts
                WHERE dedup_key = ?
                AND owner_task_id = ?
                AND status = 'PROCESSING'
                """,
                (
                    dedup_key,
                    owner_task_id
                )
            )

    def reset_incomplete(self):

        with self.db.connect() as conn:

            conn.execute(
                """
                DELETE FROM processed_alerts
                WHERE status = 'PROCESSING'
                """
            )
