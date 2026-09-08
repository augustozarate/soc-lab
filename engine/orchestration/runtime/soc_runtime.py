import time


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

                for event in events:

                    if not self.running:
                        break

                    self._process_event(
                        event
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

        self.container.event_cache.append(
            event
        )

        if len(
            self.container.event_cache
        ) > 500:

            self.container.event_cache.pop(
                0
            )

        alerts = (
            self.container.detector
            .evaluate(event)
        )

        for alert in alerts:

            alert = (
                self.container.mitre_mapper
                .enrich(alert)
            )

            self.scheduler.publish(
                event_type="alert",
                payload=alert,
                priority=50
            )