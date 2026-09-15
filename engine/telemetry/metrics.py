from collections import defaultdict
from datetime import datetime
import threading


class Metrics:

    def __init__(self):

        self.counters = defaultdict(int)
        self.gauges = {}
        self.observations = {}

        self.start_time = datetime.utcnow()

        self._lock = threading.Lock()

    # =====================================
    # COUNTERS
    # =====================================

    def inc(
        self,
        metric,
        amount=1
    ):

        with self._lock:

            self.counters[
                metric
            ] += amount

    # =====================================
    # GAUGES
    # =====================================

    def set_gauge(
        self,
        metric,
        value
    ):

        with self._lock:

            self.gauges[
                metric
            ] = value

    # =====================================
    # OBSERVATIONS
    # =====================================

    def observe(
        self,
        metric,
        value,
        label=None
    ):

        key = (
            metric,
            label
        )

        with self._lock:

            observation = (
                self.observations
                .get(key)
            )

            if observation is None:

                observation = {
                    "count": 0,
                    "total": 0.0,
                    "min": None,
                    "max": None,
                    "last": None
                }

                self.observations[
                    key
                ] = observation

            numeric_value = float(
                value
            )

            observation[
                "count"
            ] += 1

            observation[
                "total"
            ] += numeric_value

            observation[
                "last"
            ] = numeric_value

            current_min = (
                observation["min"]
            )

            if (
                current_min is None
                or numeric_value < current_min
            ):
                observation[
                    "min"
                ] = numeric_value

            current_max = (
                observation["max"]
            )

            if (
                current_max is None
                or numeric_value > current_max
            ):
                observation[
                    "max"
                ] = numeric_value

    # =====================================
    # SNAPSHOT
    # =====================================

    def snapshot(self):

        with self._lock:

            uptime = (
                datetime.utcnow()
                - self.start_time
            ).total_seconds()

            counters = dict(
                self.counters
            )

            gauges = dict(
                self.gauges
            )

            observations = {}

            for (
                metric,
                label
            ), data in self.observations.items():

                count = data[
                    "count"
                ]

                avg = (
                    data["total"] / count
                    if count
                    else 0.0
                )

                entry = {
                    "count": count,
                    "total": data["total"],
                    "min": data["min"],
                    "max": data["max"],
                    "last": data["last"],
                    "avg": avg
                }

                if label is None:

                    observations[
                        metric
                    ] = entry

                else:

                    observations.setdefault(
                        metric,
                        {}
                    )[label] = entry

            return {
                "generated_at": (
                    datetime.utcnow()
                    .isoformat()
                    + "Z"
                ),
                "uptime_seconds": uptime,
                "counters": counters,
                "gauges": gauges,
                "observations": observations
            }


metrics = Metrics()
