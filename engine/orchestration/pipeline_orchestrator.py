import time

from engine.telemetry.metrics import metrics


class PipelineOrchestrator:

    def __init__(self):

        self.stages = []

    # =========================

    def register(self, pipeline):

        self.stages.append(pipeline)

    # =========================

    def execute(self, alert):

        context = {
            "alert": alert
        }

        for stage in self.stages:

            stage_name = (
                type(stage).__name__
            )

            started = (
                time.perf_counter()
            )

            try:

                result = stage.run(
                    context
                )

            finally:

                duration = (
                    time.perf_counter()
                    - started
                )

                metrics.observe(
                    "pipeline_latency_seconds",
                    duration,
                    label=stage_name
                )

            if result is False:
                return None

        return context
