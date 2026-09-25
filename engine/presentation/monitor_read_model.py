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

    def _runtime_views(
        self,
    ):
        metrics_snapshot = (
            self.runtime_metrics_reader
            .read()
        )

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
        channels = (
            self.notification_channel_read_model
            .snapshot()
        )

        return deepcopy(
            channels
        )

    def snapshot(
        self,
        incident_limit=10,
    ):
        operator = (
            self.monitor_operator_read_model
            .snapshot(
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
