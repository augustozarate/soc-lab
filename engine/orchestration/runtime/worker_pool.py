import threading


class WorkerPool:

    def __init__(
        self,
        scheduler,
        handler,
        retry_policy,
        workers=4
    ):

        self.scheduler = scheduler
        self.handler = handler
        self.workers = workers
        self.retry_policy = retry_policy

        self.threads = []

        self._stop_event = (
            threading.Event()
        )

    def start(self):

        if any(
            t.is_alive()
            for t in self.threads
        ):
            return

        self._stop_event.clear()

        self.threads = []

        for _ in range(self.workers):
            ...

            t = threading.Thread(
                target=self._worker_loop,
                daemon=True
            )

            t.start()

            self.threads.append(t)

    def join(
        self,
        timeout=2
    ):

        for thread in self.threads:

            thread.join(
                timeout=timeout
            )

    def stop(self):

        self._stop_event.set()

    def _worker_loop(self):

        while not self._stop_event.is_set():

            task = self.scheduler.consume()

            if task is None:
                continue

            try:

                self.handler(task)

            except Exception as e:

                self.retry_policy.handle_failure(
                    task,
                    e
                )
