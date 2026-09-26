from copy import deepcopy

from engine.telemetry.runtime_health_assessor import (
    RuntimeHealthAssessor,
)
from engine.telemetry.runtime_health_view import (
    RuntimeHealthView,
)


class MonitorReadModel:

    def __init__(
        self,
        monitor_operator_read_model,
        runtime_metrics_reader,
        notification_channel_read_model,
    ):
        self.monitor_operator_read_model = (
            monitor_operator_read_model
        )
        self.runtime_metrics_reader = (
            runtime_metrics_reader
        )
        self.notification_channel_read_model = (
            notification_channel_read_model
        )

    @staticmethod
    def _unknown_operator():
        return {
            "summary": {
                "incidents": 0,
                "high_critical": 0,
                "campaigns": 0,
                "max_risk": 0,
            },
            "incidents": [],
        }

    @staticmethod
    def _unknown_channels():
        return {
            "local": "UNKNOWN",
            "email": "UNKNOWN",
            "telegram": "UNKNOWN",
            "webhook": "UNKNOWN",
            "threema": "UNKNOWN",
        }

    def _operator_snapshot(
        self,
        incident_limit,
    ):
        try:
            operator = (
                self.monitor_operator_read_model
                .snapshot(
                    incident_limit=(
                        incident_limit
                    )
                )
            )
        except Exception:
            return self._unknown_operator()

        if not isinstance(
            operator,
            dict,
        ):
            return self._unknown_operator()

        summary = operator.get(
            "summary"
        )

        incidents = operator.get(
            "incidents"
        )

        if (
            not isinstance(
                summary,
                dict,
            )
            or not isinstance(
                incidents,
                list,
            )
        ):
            return self._unknown_operator()

        return deepcopy(
            operator
        )

    def _runtime_views(
        self,
    ):
        try:
            metrics_snapshot = (
                self.runtime_metrics_reader
                .read()
            )
        except Exception:
            metrics_snapshot = None

        health = RuntimeHealthAssessor(
            metrics_snapshot
        ).assess()

        runtime = RuntimeHealthView(
            metrics_snapshot
        ).build()

        return (
            runtime,
            health,
        )

    def health(
        self,
    ):
        _, health = (
            self._runtime_views()
        )

        return deepcopy(
            health
        )

    def metrics(
        self,
    ):
        runtime, _ = (
            self._runtime_views()
        )

        return deepcopy(
            runtime
        )

    def channels(
        self,
    ):
        try:
            channels = (
                self.notification_channel_read_model
                .snapshot()
            )
        except Exception:
            channels = None

        if not isinstance(
            channels,
            dict,
        ):
            channels = (
                self._unknown_channels()
            )

        return deepcopy(
            channels
        )

    def snapshot(
        self,
        incident_limit=10,
    ):
        operator = (
            self._operator_snapshot(
                incident_limit=(
                    incident_limit
                )
            )
        )

        runtime, health = (
            self._runtime_views()
        )

        channels = (
            self.channels()
        )

        return {
            "operator": deepcopy(
                operator
            ),
            "runtime": deepcopy(
                runtime
            ),
            "health": deepcopy(
                health
            ),
            "channels": channels,
        }
