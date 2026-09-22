from datetime import (
    datetime,
    timedelta,
    timezone,
)


def _utc_now():

    return datetime.now(
        timezone.utc
    )


def _normalize_datetime(
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

    return parsed.astimezone(
        timezone.utc
    )


def _iso(
    value,
):

    return (
        value.astimezone(
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
        retry_base_seconds=30,
        retry_max_seconds=900,
        now_provider=None,
    ):

        if retry_base_seconds < 0:

            raise ValueError(
                "retry_base_seconds must be "
                "greater than or equal to 0"
            )

        if (
            retry_max_seconds
            < retry_base_seconds
        ):

            raise ValueError(
                "retry_max_seconds must be "
                "greater than or equal to "
                "retry_base_seconds"
            )

        self.db = db

        self.retry_base_seconds = (
            retry_base_seconds
        )

        self.retry_max_seconds = (
            retry_max_seconds
        )

        self.now_provider = (
            now_provider
            or _utc_now
        )

    # =========================================
    # TIME
    # =========================================

    def _now(
        self,
    ):

        return _normalize_datetime(
            self.now_provider(),
            "now_provider",
        )

    def _retry_delay(
        self,
        attempt_count,
    ):

        if self.retry_base_seconds == 0:
            return 0

        attempt_count = max(
            int(
                attempt_count
                or 1
            ),
            1,
        )

        delay = (
            self.retry_base_seconds
            * (
                2
                ** (
                    attempt_count
                    - 1
                )
            )
        )

        return min(
            delay,
            self.retry_max_seconds,
        )

    # =========================================
    # LEGACY / IMMEDIATE CLAIM
    # =========================================

    def claim(
        self,
        dedup_key,
        channel,
        incident_id=None,
        severity=None,
    ):

        """
        Low-level immediate claim kept for
        repository compatibility/tests.

        Production NotificationService uses
        claim_delivery(), which applies durable
        retry eligibility.
        """

        return self._claim_immediate(
            dedup_key=dedup_key,
            channel=channel,
            incident_id=incident_id,
            severity=severity,
        )

    # =========================================
    # RETRY-AWARE CLAIM
    # =========================================

    def claim_delivery(
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

        now = self._now()
        now_iso = _iso(
            now
        )

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
                    now_iso,
                    now_iso,
                    now_iso,
                ),
            )

            if cursor.rowcount == 1:

                return {
                    "status": "CLAIMED",
                    "attempt_count": 1,
                }

            row = conn.execute(
                """
                SELECT
                    status,
                    attempt_count,
                    last_attempt_at,
                    provider_retry_at
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

                return {
                    "status": "SUPPRESSED",
                    "reason": (
                        "Delivery state unavailable"
                    ),
                }

            status = row[
                "status"
            ]

            attempt_count = int(
                row[
                    "attempt_count"
                ]
                or 0
            )

            if status == "SUCCESS":

                return {
                    "status": "SUPPRESSED",
                    "reason": (
                        "Notification already "
                        "delivered"
                    ),
                    "attempt_count": (
                        attempt_count
                    ),
                }

            if status == "PENDING":

                return {
                    "status": "SUPPRESSED",
                    "reason": (
                        "Notification delivery "
                        "already in progress"
                    ),
                    "attempt_count": (
                        attempt_count
                    ),
                }

            if status not in (
                "FAILED",
                "SKIPPED",
                "RATE_LIMITED",
            ):

                return {
                    "status": "SUPPRESSED",
                    "reason": (
                        "Notification delivery "
                        f"state={status}"
                    ),
                    "attempt_count": (
                        attempt_count
                    ),
                }

            last_attempt = (
                _normalize_datetime(
                    row[
                        "last_attempt_at"
                    ],
                    "last_attempt_at",
                )
            )

            provider_retry_value = row[
                "provider_retry_at"
            ]

            if (
                status == "RATE_LIMITED"
                and provider_retry_value
            ):

                retry_at = (
                    _normalize_datetime(
                        provider_retry_value,
                        "provider_retry_at",
                    )
                )

                if now < retry_at:

                    return {
                        "status": "DEFERRED",
                        "reason": (
                            "Provider retry "
                            "boundary active"
                        ),
                        "attempt_count": (
                            attempt_count
                        ),
                        "retry_at": _iso(
                            retry_at
                        ),
                    }

            else:

                delay = self._retry_delay(
                    attempt_count
                )

                retry_at = (
                    last_attempt
                    + timedelta(
                        seconds=delay
                    )
                )

                if now < retry_at:

                    return {
                        "status": "DEFERRED",
                        "reason": (
                            "Notification retry "
                            "backoff active"
                        ),
                        "attempt_count": (
                            attempt_count
                        ),
                        "retry_at": _iso(
                            retry_at
                        ),
                    }

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
                    last_error = NULL,
                    provider_retry_at = NULL
                WHERE dedup_key = ?
                  AND channel = ?
                  AND status IN (
                      'FAILED',
                      'SKIPPED',
                      'RATE_LIMITED'
                  )
                  AND last_attempt_at = ?
                """,
                (
                    incident_id,
                    severity,
                    now_iso,
                    now_iso,
                    dedup_key,
                    channel,
                    row[
                        "last_attempt_at"
                    ],
                ),
            )

            if cursor.rowcount != 1:

                return {
                    "status": "SUPPRESSED",
                    "reason": (
                        "Notification delivery "
                        "was claimed concurrently"
                    ),
                }

            return {
                "status": "CLAIMED",
                "attempt_count": (
                    attempt_count
                    + 1
                ),
            }

    def _claim_immediate(
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

        now = _iso(
            self._now()
        )

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

        now = _iso(
            self._now()
        )

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

        now = _iso(
            self._now()
        )

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
                    str(
                        error
                    ),
                    dedup_key,
                    channel,
                ),
            )

            return (
                cursor.rowcount
                == 1
            )

    def mark_rate_limited(
        self,
        dedup_key,
        channel,
        reason,
        retry_after_seconds=None,
    ):

        now_value = self._now()

        provider_retry_at = None

        if retry_after_seconds is not None:

            if (
                isinstance(
                    retry_after_seconds,
                    bool,
                )
                or not isinstance(
                    retry_after_seconds,
                    int,
                )
            ):

                raise ValueError(
                    "retry_after_seconds must be "
                    "an integer"
                )

            if not (
                1
                <= retry_after_seconds
                <= 86400
            ):

                raise ValueError(
                    "retry_after_seconds must be "
                    "between 1 and 86400"
                )

            provider_retry_at = _iso(
                now_value
                + timedelta(
                    seconds=(
                        retry_after_seconds
                    )
                )
            )

        now = _iso(
            now_value
        )

        with self.db.connect() as conn:

            cursor = conn.execute(
                """
                UPDATE notification_deliveries
                SET
                    status = 'RATE_LIMITED',
                    backend = NULL,
                    updated_at = ?,
                    delivered_at = NULL,
                    last_error = ?,
                    provider_retry_at = ?
                WHERE dedup_key = ?
                  AND channel = ?
                  AND status = 'PENDING'
                """,
                (
                    now,
                    str(
                        reason
                    ),
                    provider_retry_at,
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

        now = _iso(
            self._now()
        )

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
                    str(
                        reason
                    ),
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

        now = _iso(
            self._now()
        )

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
                    last_error,
                    provider_retry_at
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
                    last_error,
                    provider_retry_at
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
