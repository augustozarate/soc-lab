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


class NotificationRateLimitRepository:

    def __init__(
        self,
        db,
        window_seconds=60,
        limits=None,
        now_provider=None,
    ):

        if window_seconds <= 0:

            raise ValueError(
                "window_seconds must be "
                "greater than 0"
            )

        self.db = db

        self.window_seconds = (
            window_seconds
        )

        self.limits = dict(
            limits or {}
        )

        self.now_provider = (
            now_provider
            or _utc_now
        )

        for (
            channel,
            limit,
        ) in self.limits.items():

            if limit < 0:

                raise ValueError(
                    f"rate limit for {channel} "
                    "must be greater than or "
                    "equal to 0"
                )

    def _now(
        self,
    ):

        return _normalize_datetime(
            self.now_provider(),
            "now_provider",
        )

    def check_and_consume(
        self,
        channel,
    ):

        limit = self.limits.get(
            channel
        )

        if limit is None:

            return {
                "status": "UNLIMITED",
            }

        if limit == 0:

            return {
                "status": "RATE_LIMITED",
                "reason": (
                    "Notification channel "
                    "is disabled by rate limit"
                ),
            }

        now = self._now()
        now_iso = _iso(
            now
        )

        with self.db.connect() as conn:

            row = conn.execute(
                """
                SELECT
                    window_start,
                    delivery_count
                FROM notification_rate_limits
                WHERE channel = ?
                """,
                (
                    channel,
                ),
            ).fetchone()

            if row is None:

                conn.execute(
                    """
                    INSERT INTO
                    notification_rate_limits (
                        channel,
                        window_start,
                        delivery_count,
                        updated_at
                    )
                    VALUES (
                        ?,
                        ?,
                        1,
                        ?
                    )
                    """,
                    (
                        channel,
                        now_iso,
                        now_iso,
                    ),
                )

                return {
                    "status": "ALLOWED",
                    "remaining": (
                        limit - 1
                    ),
                    "reset_at": _iso(
                        now
                        + timedelta(
                            seconds=(
                                self
                                .window_seconds
                            )
                        )
                    ),
                }

            window_start = (
                _normalize_datetime(
                    row[
                        "window_start"
                    ],
                    "window_start",
                )
            )

            reset_at = (
                window_start
                + timedelta(
                    seconds=(
                        self.window_seconds
                    )
                )
            )

            if now >= reset_at:

                conn.execute(
                    """
                    UPDATE notification_rate_limits
                    SET
                        window_start = ?,
                        delivery_count = 1,
                        updated_at = ?
                    WHERE channel = ?
                    """,
                    (
                        now_iso,
                        now_iso,
                        channel,
                    ),
                )

                return {
                    "status": "ALLOWED",
                    "remaining": (
                        limit - 1
                    ),
                    "reset_at": _iso(
                        now
                        + timedelta(
                            seconds=(
                                self
                                .window_seconds
                            )
                        )
                    ),
                }

            count = int(
                row[
                    "delivery_count"
                ]
                or 0
            )

            if count >= limit:

                return {
                    "status": "RATE_LIMITED",
                    "reason": (
                        "Notification channel "
                        "rate limit reached"
                    ),
                    "remaining": 0,
                    "reset_at": _iso(
                        reset_at
                    ),
                }

            cursor = conn.execute(
                """
                UPDATE notification_rate_limits
                SET
                    delivery_count = (
                        delivery_count + 1
                    ),
                    updated_at = ?
                WHERE channel = ?
                  AND window_start = ?
                  AND delivery_count = ?
                """,
                (
                    now_iso,
                    channel,
                    row[
                        "window_start"
                    ],
                    count,
                ),
            )

            if cursor.rowcount != 1:

                return {
                    "status": "RATE_LIMITED",
                    "reason": (
                        "Rate limit state "
                        "changed concurrently"
                    ),
                    "remaining": 0,
                    "reset_at": _iso(
                        reset_at
                    ),
                }

            return {
                "status": "ALLOWED",
                "remaining": (
                    limit
                    - count
                    - 1
                ),
                "reset_at": _iso(
                    reset_at
                ),
            }

    def get(
        self,
        channel,
    ):

        with self.db.connect() as conn:

            row = conn.execute(
                """
                SELECT
                    channel,
                    window_start,
                    delivery_count,
                    updated_at
                FROM notification_rate_limits
                WHERE channel = ?
                """,
                (
                    channel,
                ),
            ).fetchone()

        if row is None:
            return None

        return dict(
            row
        )
