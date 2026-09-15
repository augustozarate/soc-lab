class RuntimeHealthView:

    def __init__(
        self,
        snapshot
    ):

        self.snapshot = (
            snapshot
            if isinstance(snapshot, dict)
            else {}
        )

    # =====================================

    def build(self):

        counters = self._mapping(
            "counters"
        )

        gauges = self._mapping(
            "gauges"
        )

        observations = self._mapping(
            "observations"
        )

        task_latency = (
            observations.get(
                "task_latency_seconds"
            )
            or {}
        )

        return {
            "generated_at": (
                self.snapshot.get(
                    "generated_at"
                )
            ),

            "uptime": self._format_uptime(
                self.snapshot.get(
                    "uptime_seconds",
                    0
                )
            ),

            "queue_depth": gauges.get(
                "queue_depth",
                0
            ),

            "checkpoint_lag": (
                self._format_bytes(
                    gauges.get(
                        "checkpoint_lag_bytes",
                        0
                    )
                )
            ),

            "events_read": counters.get(
                "events_read_total",
                0
            ),

            "alerts_generated": counters.get(
                "alerts_generated_total",
                0
            ),

            "tasks_completed": counters.get(
                "tasks_completed_total",
                0
            ),

            "task_attempt_failures": (
                counters.get(
                    "task_attempt_failures_total",
                    0
                )
            ),

            "tasks_deduplicated": counters.get(
                "tasks_deduplicated_total",
                0
            ),

            "avg_task_latency": (
                self._format_latency(
                    task_latency.get(
                        "avg"
                    )
                )
            )
        }

    # =====================================

    def _mapping(
        self,
        key
    ):

        value = self.snapshot.get(
            key
        )

        if isinstance(
            value,
            dict
        ):
            return value

        return {}

    # =====================================

    def _format_uptime(
        self,
        seconds
    ):

        try:
            total_seconds = max(
                0,
                int(float(seconds))
            )
        except (
            TypeError,
            ValueError
        ):
            total_seconds = 0

        hours, remainder = divmod(
            total_seconds,
            3600
        )

        minutes, seconds = divmod(
            remainder,
            60
        )

        return (
            f"{hours:02d}:"
            f"{minutes:02d}:"
            f"{seconds:02d}"
        )

    # =====================================

    def _format_bytes(
        self,
        value
    ):

        try:
            size = max(
                0.0,
                float(value)
            )
        except (
            TypeError,
            ValueError
        ):
            size = 0.0

        units = (
            "B",
            "KiB",
            "MiB",
            "GiB"
        )

        for unit in units:

            if (
                size < 1024
                or unit == units[-1]
            ):

                if unit == "B":
                    return (
                        f"{int(size)} {unit}"
                    )

                return (
                    f"{size:.1f} {unit}"
                )

            size /= 1024

        return "0 B"

    # =====================================

    def _format_latency(
        self,
        seconds
    ):

        if seconds is None:
            return "N/A"

        try:
            milliseconds = (
                float(seconds)
                * 1000
            )
        except (
            TypeError,
            ValueError
        ):
            return "N/A"

        if milliseconds < 0:
            return "N/A"

        return (
            f"{milliseconds:.1f} ms"
        )
