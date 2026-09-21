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


def _normalize_utc_iso(
    value,
    field_name,
):

    if isinstance(
        value,
        datetime,
    ):

        parsed = value

    elif isinstance(
        value,
        str,
    ):

        try:

            parsed = datetime.fromisoformat(
                value
            )

        except ValueError as exc:

            raise ValueError(
                f"{field_name} must be "
                "a valid ISO-8601 datetime"
            ) from exc

    else:

        raise TypeError(
            f"{field_name} must be "
            "a datetime or ISO-8601 string"
        )

    if (
        parsed.tzinfo is None
        or parsed.utcoffset() is None
    ):

        raise ValueError(
            f"{field_name} must be "
            "timezone-aware"
        )

    return (
        parsed.astimezone(
            timezone.utc
        )
        .isoformat(
            timespec="microseconds"
        )
    )


class ResponseBlockRepository:

    def __init__(
        self,
        db,
    ):

        self.db = db

    def upsert_active(
        self,
        target,
        expires_at,
        execution_mode,
        backend,
        rule_name=None,
        source_incident_id=None,
    ):

        expires_at = (
            _normalize_utc_iso(
                expires_at,
                "expires_at",
            )
        )

        now = _utc_now_iso()

        with self.db.connect() as conn:

            conn.execute(
                """
                INSERT INTO response_blocks (
                    target,
                    desired_state,
                    status,
                    created_at,
                    updated_at,
                    expires_at,
                    execution_mode,
                    backend,
                    rule_name,
                    source_incident_id,
                    last_error
                )
                VALUES (
                    ?,
                    'BLOCKED',
                    'ACTIVE',
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    NULL
                )

                ON CONFLICT(target) DO UPDATE SET

                    desired_state = 'BLOCKED',
                    status = 'ACTIVE',
                    updated_at = excluded.updated_at,
                    expires_at = excluded.expires_at,
                    execution_mode = excluded.execution_mode,
                    backend = excluded.backend,
                    rule_name = excluded.rule_name,
                    source_incident_id = excluded.source_incident_id,
                    last_error = NULL
                """,
                (
                    target,
                    now,
                    now,
                    expires_at,
                    execution_mode,
                    backend,
                    rule_name,
                    source_incident_id,
                ),
            )

        return self.get(
            target
        )

    def get(
        self,
        target,
    ):

        with self.db.connect() as conn:

            row = conn.execute(
                """
                SELECT
                    target,
                    desired_state,
                    status,
                    created_at,
                    updated_at,
                    expires_at,
                    execution_mode,
                    backend,
                    rule_name,
                    source_incident_id,
                    last_error
                FROM response_blocks
                WHERE target = ?
                """,
                (
                    target,
                ),
            ).fetchone()

        if row is None:
            return None

        return dict(
            row
        )

    def list_active(self):

        with self.db.connect() as conn:

            rows = conn.execute(
                """
                SELECT
                    target,
                    desired_state,
                    status,
                    created_at,
                    updated_at,
                    expires_at,
                    execution_mode,
                    backend,
                    rule_name,
                    source_incident_id,
                    last_error
                FROM response_blocks
                WHERE status = 'ACTIVE'
                ORDER BY
                    expires_at ASC,
                    target ASC
                """
            ).fetchall()

        return [
            dict(row)
            for row in rows
        ]

    def list_expired(
        self,
        now,
    ):

        now = _normalize_utc_iso(
            now,
            "now",
        )

        with self.db.connect() as conn:

            rows = conn.execute(
                """
                SELECT
                    target,
                    desired_state,
                    status,
                    created_at,
                    updated_at,
                    expires_at,
                    execution_mode,
                    backend,
                    rule_name,
                    source_incident_id,
                    last_error
                FROM response_blocks
                WHERE desired_state = 'BLOCKED'
                  AND status IN (
                      'ACTIVE',
                      'FAILED'
                  )
                  AND expires_at <= ?
                ORDER BY
                    expires_at ASC,
                    target ASC
                """,
                (
                    now,
                ),
            ).fetchall()

        return [
            dict(row)
            for row in rows
        ]

    def mark_expired(
        self,
        target,
        now,
    ):

        now = _normalize_utc_iso(
            now,
            "now",
        )

        with self.db.connect() as conn:

            cursor = conn.execute(
                """
                UPDATE response_blocks
                SET
                    desired_state = 'UNBLOCKED',
                    status = 'EXPIRED',
                    updated_at = ?,
                    last_error = NULL
                WHERE target = ?
                  AND desired_state = 'BLOCKED'
                  AND status IN (
                      'ACTIVE',
                      'FAILED'
                  )
                """,
                (
                    now,
                    target,
                ),
            )

            changed = (
                cursor.rowcount
                == 1
            )

        return changed

    def mark_released(
        self,
        target,
        now,
    ):

        now = _normalize_utc_iso(
            now,
            "now",
        )

        with self.db.connect() as conn:

            cursor = conn.execute(
                """
                UPDATE response_blocks
                SET
                    desired_state = 'UNBLOCKED',
                    status = 'RELEASED',
                    updated_at = ?,
                    last_error = NULL
                WHERE target = ?
                  AND status != 'RELEASED'
                """,
                (
                    now,
                    target,
                ),
            )

            changed = (
                cursor.rowcount
                == 1
            )

        return changed

    def mark_failed(
        self,
        target,
        error,
        now,
    ):

        now = _normalize_utc_iso(
            now,
            "now",
        )

        with self.db.connect() as conn:

            cursor = conn.execute(
                """
                UPDATE response_blocks
                SET
                    status = 'FAILED',
                    updated_at = ?,
                    last_error = ?
                WHERE target = ?
                """,
                (
                    now,
                    str(error),
                    target,
                ),
            )

            changed = (
                cursor.rowcount
                == 1
            )

        return changed
