from datetime import (
    datetime,
    timezone,
)


def _utc_now_iso():

    return (
        datetime.now(
            timezone.utc
        )
        .isoformat(
            timespec="microseconds"
        )
    )


class NotificationDeliveryRepository:

    def __init__(
        self,
        db,
    ):

        self.db = db

    # =========================================
    # CLAIM
    # =========================================

    def claim(
        self,
        dedup_key,
        channel,
        incident_id=None,
        severity=None,
    ):

        if not dedup_key:
            raise ValueError(
                "dedup_key is required"
            )

        if not channel:
            raise ValueError(
                "channel is required"
            )

        now = _utc_now_iso()

        with self.db.connect() as conn:

            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO
                notification_deliveries (
                    dedup_key,
                    channel,
                    incident_id,
                    severity,
                    status,
                    backend,
                    attempt_count,
                    created_at,
                    updated_at,
                    last_attempt_at,
                    delivered_at,
                    last_error
                )
                VALUES (
                    ?,
                    ?,
                    ?,
                    ?,
                    'PENDING',
                    NULL,
                    1,
                    ?,
                    ?,
                    ?,
                    NULL,
                    NULL
                )
                """,
                (
                    dedup_key,
                    channel,
                    incident_id,
                    severity,
                    now,
                    now,
                    now,
                ),
            )

            if cursor.rowcount == 1:
                return True

            cursor = conn.execute(
                """
                UPDATE notification_deliveries
                SET
                    incident_id = ?,
                    severity = ?,
                    status = 'PENDING',
                    backend = NULL,
                    attempt_count = (
                        attempt_count + 1
                    ),
                    updated_at = ?,
                    last_attempt_at = ?,
                    delivered_at = NULL,
                    last_error = NULL
                WHERE dedup_key = ?
                  AND channel = ?
                  AND status IN (
                      'FAILED',
                      'SKIPPED'
                  )
                """,
                (
                    incident_id,
                    severity,
                    now,
                    now,
                    dedup_key,
                    channel,
                ),
            )

            return (
                cursor.rowcount
                == 1
            )

    # =========================================
    # OUTCOMES
    # =========================================

    def mark_success(
        self,
        dedup_key,
        channel,
        backend=None,
    ):

        now = _utc_now_iso()

        with self.db.connect() as conn:

            cursor = conn.execute(
                """
                UPDATE notification_deliveries
                SET
                    status = 'SUCCESS',
                    backend = ?,
                    updated_at = ?,
                    delivered_at = ?,
                    last_error = NULL
                WHERE dedup_key = ?
                  AND channel = ?
                  AND status = 'PENDING'
                """,
                (
                    backend,
                    now,
                    now,
                    dedup_key,
                    channel,
                ),
            )

            return (
                cursor.rowcount
                == 1
            )

    def mark_failed(
        self,
        dedup_key,
        channel,
        error,
        backend=None,
    ):

        now = _utc_now_iso()

        with self.db.connect() as conn:

            cursor = conn.execute(
                """
                UPDATE notification_deliveries
                SET
                    status = 'FAILED',
                    backend = ?,
                    updated_at = ?,
                    delivered_at = NULL,
                    last_error = ?
                WHERE dedup_key = ?
                  AND channel = ?
                  AND status = 'PENDING'
                """,
                (
                    backend,
                    now,
                    str(error),
                    dedup_key,
                    channel,
                ),
            )

            return (
                cursor.rowcount
                == 1
            )

    def mark_skipped(
        self,
        dedup_key,
        channel,
        reason,
    ):

        now = _utc_now_iso()

        with self.db.connect() as conn:

            cursor = conn.execute(
                """
                UPDATE notification_deliveries
                SET
                    status = 'SKIPPED',
                    backend = NULL,
                    updated_at = ?,
                    delivered_at = NULL,
                    last_error = ?
                WHERE dedup_key = ?
                  AND channel = ?
                  AND status = 'PENDING'
                """,
                (
                    now,
                    str(reason),
                    dedup_key,
                    channel,
                ),
            )

            return (
                cursor.rowcount
                == 1
            )

    # =========================================
    # RECOVERY
    # =========================================

    def reset_incomplete(
        self,
    ):

        now = _utc_now_iso()

        with self.db.connect() as conn:

            cursor = conn.execute(
                """
                UPDATE notification_deliveries
                SET
                    status = 'FAILED',
                    updated_at = ?,
                    delivered_at = NULL,
                    last_error = (
                        CASE
                            WHEN last_error IS NULL
                            THEN 'Recovered incomplete delivery'
                            ELSE last_error
                        END
                    )
                WHERE status = 'PENDING'
                """,
                (
                    now,
                ),
            )

            return cursor.rowcount

    # =========================================
    # READS
    # =========================================

    def get(
        self,
        dedup_key,
        channel,
    ):

        with self.db.connect() as conn:

            row = conn.execute(
                """
                SELECT
                    dedup_key,
                    channel,
                    incident_id,
                    severity,
                    status,
                    backend,
                    attempt_count,
                    created_at,
                    updated_at,
                    last_attempt_at,
                    delivered_at,
                    last_error
                FROM notification_deliveries
                WHERE dedup_key = ?
                  AND channel = ?
                """,
                (
                    dedup_key,
                    channel,
                ),
            ).fetchone()

        if row is None:
            return None

        return dict(
            row
        )

    def list_for_incident(
        self,
        incident_id,
    ):

        with self.db.connect() as conn:

            rows = conn.execute(
                """
                SELECT
                    dedup_key,
                    channel,
                    incident_id,
                    severity,
                    status,
                    backend,
                    attempt_count,
                    created_at,
                    updated_at,
                    last_attempt_at,
                    delivered_at,
                    last_error
                FROM notification_deliveries
                WHERE incident_id = ?
                ORDER BY
                    created_at ASC,
                    channel ASC
                """,
                (
                    incident_id,
                ),
            ).fetchall()

        return [
            dict(row)
            for row in rows
        ]
