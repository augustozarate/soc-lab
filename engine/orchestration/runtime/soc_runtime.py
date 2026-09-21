import time
import os

from engine.telemetry.metrics import metrics


class SOCRuntime:

    def __init__(
        self,
        container,
        cli,
        watcher,
        scheduler,
        worker_pool,
        logger
    ):

        self.container = container
        self.cli = cli
        self.watcher = watcher
        self.scheduler = scheduler
        self.worker_pool = worker_pool
        self.log = logger

        self.running = False

    # =====================================

    def start(self):

        if self.running:
            return

        self.running = True

        self.log(
            "[RUNTIME] Starting SOC Runtime"
        )

        try:

            self.worker_pool.start()

            self._start_cli()

            self._start_rule_watcher()

            self._event_loop()

        except KeyboardInterrupt:

            self.log(
                "[RUNTIME] Keyboard interrupt received"
            )

        finally:

            self.stop()

    # =====================================

    def stop(self):

        if not self.running:
            return

        self.running = False

        self.worker_pool.stop()
        self.worker_pool.join()

        self.watcher.stop()

        self.log(
            "[RUNTIME] Shutdown complete"
        )

    # =====================================

    def _start_cli(self):

        self.cli.start_async()

    # =====================================

    def _start_rule_watcher(self):

        self.watcher.start_async()

    # =====================================

    def _event_loop(self):

        while self.running:

            try:

                events = (
                    self.container.reader
                    .read_new_events()
                )
                self._update_runtime_gauges()

                batch_completed = True
                batch_tasks = []

                for event in events:

                    if not self.running:
                        batch_completed = False
                        break

                    tasks = self._process_event(
                        event
                    )

                    batch_tasks.extend(
                        tasks
                    )

                tasks_completed = (
                    self._wait_for_tasks(
                        batch_tasks
                    )
                )

                if (
                    events
                    and batch_completed
                    and tasks_completed
                ):
                    self.container.reader.commit()
                    self._update_runtime_gauges()

                (
                    self.container
                    .response_block_expiration
                    .sweep()
                )

            except Exception as error:

                self.log(
                    "[RUNTIME] Event loop error: "
                    f"{error}"
                )

            time.sleep(1)

    # =====================================

    def _process_event(
        self,
        event
    ):
        metrics.inc(
            "events_read_total"
        )

        self.container.event_cache.append(
            event
        )

        if len(
            self.container.event_cache
        ) > 500:

            self.container.event_cache.pop(
                0
            )

        # =====================================
        # RULE-BASED DETECTION
        # =====================================

        rule_alerts = (
            self.container.detector
            .evaluate(event)
        )

        # =====================================
        # UEBA / BEHAVIORAL DETECTION
        # =====================================

        ueba_alerts = (
            self.container.behavior_engine
            .analyze(event)
        )

        # =====================================
        # UNIFIED ALERT FLOW
        # =====================================

        alerts = (
            rule_alerts
            + ueba_alerts
        )

        if alerts:

            metrics.inc(
                "alerts_generated_total",
                len(alerts)
            )

        published_tasks = []

        for alert in alerts:

            alert = (
                self.container.mitre_mapper
                .enrich(alert)
            )

            task = self.scheduler.publish(
                event_type="alert",
                payload=alert,
                priority=50
            )

            published_tasks.append(
                task
            )

        return published_tasks

    # =====================================

    def _wait_for_tasks(
        self,
        tasks,
        warning_interval=30
    ):

        if not tasks:
            return True

        next_warning = (
            time.time()
            + warning_interval
        )

        terminal_states = {
            "COMPLETED",
            "FAILED"
        }

        while self.running:

            if all(
                task["state"]
                in terminal_states
                for task in tasks
            ):
                return True

            if time.time() >= next_warning:

                pending = [
                    task
                    for task in tasks
                    if task["state"]
                    not in terminal_states
                ]

                self.log(
                    "[RUNTIME] Waiting for "
                    f"{len(pending)} task(s) "
                    "before checkpoint commit"
                )

                next_warning = (
                    time.time()
                    + warning_interval
                )

            time.sleep(0.1)

        return False

    # =====================================

    def _update_runtime_gauges(self):

        reader = (
            self.container.reader
        )

        metrics.set_gauge(
            "queue_depth",
            self.scheduler.depth()
        )

        checkpoint_position = (
            reader.position
        )

        metrics.set_gauge(
            "checkpoint_position",
            checkpoint_position
        )

        try:

            stream_size = os.path.getsize(
                reader.filepath
            )

        except OSError:

            stream_size = 0

        metrics.set_gauge(
            "stream_size",
            stream_size
        )

        checkpoint_lag = max(
            0,
            stream_size
            - checkpoint_position
        )

        metrics.set_gauge(
            "checkpoint_lag_bytes",
            checkpoint_lag
        )

        self._write_runtime_metrics()

    # =====================================

    def _write_runtime_metrics(self):

        try:

            snapshot = (
                metrics.snapshot()
            )

            self.container.runtime_metrics_writer.write(
                snapshot
            )

        except Exception as error:

            self.log(
                "[METRICS] Snapshot update failed: "
                f"{error}"
            )
