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
        operator_read_model,
        runtime_metrics_reader,
        notification_channel_read_model,
    ):
        self.operator_read_model = (
            operator_read_model
        )
        self.runtime_metrics_reader = (
            runtime_metrics_reader
        )
        self.notification_channel_read_model = (
            notification_channel_read_model
        )

    def snapshot(
        self,
        recent_event_limit=10,
    ):
        operator = (
            self.operator_read_model
            .snapshot(
                recent_event_limit=(
                    recent_event_limit
                )
            )
        )

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

        channels = (
            self.notification_channel_read_model
            .snapshot()
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
            "channels": deepcopy(
                channels
            ),
        }
