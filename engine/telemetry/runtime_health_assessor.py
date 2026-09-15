from datetime import datetime, timezone


class RuntimeHealthAssessor:

    def __init__(
        self,
        snapshot,
        stale_after_seconds=5.0,
        queue_warning_threshold=10,
        checkpoint_lag_warning_bytes=4096
    ):

        self.snapshot = (
            snapshot
            if isinstance(snapshot, dict)
            else {}
        )

        self.stale_after_seconds = float(
            stale_after_seconds
        )

        self.queue_warning_threshold = int(
            queue_warning_threshold
        )

        self.checkpoint_lag_warning_bytes = int(
            checkpoint_lag_warning_bytes
        )

    # =====================================

    def assess(
        self,
        now=None
    ):

        if not self.snapshot:
            return {
                "status": "UNKNOWN",
                "reasons": [
                    "runtime metrics unavailable"
                ],
                "snapshot_age_seconds": None
            }

        age = self._snapshot_age(
            now
        )

        if age is None:
            return {
                "status": "UNKNOWN",
                "reasons": [
                    "invalid or missing generated_at"
                ],
                "snapshot_age_seconds": None
            }

        if age > self.stale_after_seconds:
            return {
                "status": "STALE",
                "reasons": [
                    "runtime heartbeat is stale"
                ],
                "snapshot_age_seconds": age
            }

        gauges = self.snapshot.get(
            "gauges"
        )

        if not isinstance(
            gauges,
            dict
        ):
            gauges = {}

        reasons = []

        queue_depth = self._number(
            gauges.get(
                "queue_depth",
                0
            )
        )

        checkpoint_lag = self._number(
            gauges.get(
                "checkpoint_lag_bytes",
                0
            )
        )

        if (
            queue_depth
            >= self.queue_warning_threshold
        ):
            reasons.append(
                "scheduler queue depth is elevated"
            )

        if (
            checkpoint_lag
            >= self.checkpoint_lag_warning_bytes
        ):
            reasons.append(
                "event checkpoint lag is elevated"
            )

        return {
            "status": (
                "DEGRADED"
                if reasons
                else "HEALTHY"
            ),
            "reasons": reasons,
            "snapshot_age_seconds": age
        }

    # =====================================

    def _snapshot_age(
        self,
        now
    ):

        generated_at = self.snapshot.get(
            "generated_at"
        )

        if not isinstance(
            generated_at,
            str
        ):
            return None

        try:

            timestamp = (
                datetime.fromisoformat(
                    generated_at.replace(
                        "Z",
                        "+00:00"
                    )
                )
            )

        except ValueError:
            return None

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(
                tzinfo=timezone.utc
            )

        if now is None:
            now = datetime.now(
                timezone.utc
            )

        elif now.tzinfo is None:
            now = now.replace(
                tzinfo=timezone.utc
            )

        return max(
            0.0,
            (
                now
                - timestamp
            ).total_seconds()
        )

    # =====================================

    @staticmethod
    def _number(
        value
    ):

        try:
            return float(
                value
            )

        except (
            TypeError,
            ValueError
        ):
            return 0.0
