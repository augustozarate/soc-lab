import time

from engine.telemetry.metrics import metrics
from engine.bootstrap.builders.core_builder import build_core
from engine.bootstrap.builders.repository_builder import build_repositories
from engine.bootstrap.builders.infrastructure_builder import build_infrastructure
from engine.bootstrap.builders.service_builder import build_services
from engine.bootstrap.builders.correlation_builder import build_correlation
from engine.bootstrap.builders.pipeline_builder import build_pipelines
from engine.bootstrap.builders.subscriber_builder import build_subscribers
from engine.bootstrap.builders.runtime_builder import build_runtime
from engine.services.monitor_snapshot import (
    MonitorSnapshotWriter
)
from engine.telemetry.runtime_metrics_writer import (
    RuntimeMetricsWriter
)


class Container:

    def __init__(
        self,
        stream_file,
        detection_path,
        mitre_file,
        dlq_file,
        db_file,
        event_cache,
        monitor_snapshot_file,
        runtime_metrics_file,
        event_reader_checkpoint_file
    ):

        self.event_cache = event_cache

        build_core(self)

        build_repositories(
            self,
            db_file
        )

        build_infrastructure(
            self,
            stream_file,
            event_reader_checkpoint_file,
            detection_path,
            mitre_file
        )

        build_services(self)

        self.monitor_snapshot_writer = (
            MonitorSnapshotWriter(
                monitor_snapshot_file
            )
        )

        self.runtime_metrics_writer = (
            RuntimeMetricsWriter(
                runtime_metrics_file
            )
        )

        build_correlation(self)

        build_pipelines(self)

        build_subscribers(self)

        build_runtime(
            self,
            dlq_file
        )

    def reload_rules(self):

        self.rules = (
            self.loader.load()
        )

        self.detector.update_rules(
            self.rules
        )

    def process_task(self, task):

        task["state"] = "RUNNING"

        started = (
            time.perf_counter()
        )

        alert = task["payload"]

        dedup_key = (
            self.processed_alert_repository
            .build_key(alert)
        )

        claimed = False

        if dedup_key:

            claimed = (
                self.processed_alert_repository
                .claim(
                    dedup_key=dedup_key,
                    alert_type=(
                        alert.get("rule_id")
                        or alert.get("type")
                    ),
                    ip=alert.get("ip"),
                    source_record_id=alert.get(
                        "source_record_id"
                    ),
                    source_event_id=alert.get(
                        "source_event_id"
                    ),
                    owner_task_id=task["task_id"]
                )
            )

            if not claimed:
                duration = (
                    time.perf_counter()
                    - started
                )

                metrics.inc(
                    "tasks_deduplicated_total"
                )

                metrics.inc(
                    "tasks_completed_total"
                )

                metrics.observe(
                    "task_latency_seconds",
                    duration
                )

                task["state"] = "COMPLETED"
                return None

        try:

            result = self.orchestrator.execute(
                alert
            )

            if dedup_key:
                self.processed_alert_repository.complete(
                    dedup_key,
                    task["task_id"]
                )

        except Exception:

            duration = (
                time.perf_counter()
                - started
            )

            metrics.inc(
                "task_attempt_failures_total"
            )

            metrics.observe(
                "task_latency_seconds",
                duration
            )

            if (
                dedup_key
                and claimed
            ):
                self.processed_alert_repository.release(
                    dedup_key,
                    task["task_id"]
                )

            raise

        try:

            snapshot = (
                self.monitor_snapshot_builder
                .build()
            )

            self.monitor_snapshot_writer.write(
                snapshot
            )

        except Exception as error:

            print(
                "[MONITOR] Snapshot update failed: "
                f"{error}"
            )

        duration = (
            time.perf_counter()
            - started
        )

        metrics.inc(
            "tasks_completed_total"
        )

        metrics.observe(
            "task_latency_seconds",
            duration
        )

        task["state"] = "COMPLETED"

        return result
