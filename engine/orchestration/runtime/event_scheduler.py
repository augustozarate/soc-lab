from itertools import count
from queue import PriorityQueue, Empty

from engine.telemetry.metrics import metrics

from engine.orchestration.runtime.task_context import (
    TaskContext
)


class EventScheduler:

    def __init__(
        self,
        event_repository=None
    ):

        self.queue = PriorityQueue()
        self.event_repository = (
            event_repository
        )

        self._sequence = count()

    def publish(
        self,
        event_type,
        payload,
        priority=50
    ):

        task = TaskContext(
            event_type=event_type,
            payload=payload,
            priority=priority
        )

        self.queue.put(
            (
                -priority,
                next(self._sequence),
                task
            )
        )

        metrics.set_gauge(
            "queue_depth",
            self.depth()
        )

        if self.event_repository:

            self.event_repository.save(
                event_type,
                payload
            )

        return task

    def consume(
        self,
        timeout=0.5
    ):

        try:

            _, _, task = (
                self.queue.get(
                    timeout=timeout
                )
            )

            metrics.set_gauge(
                "queue_depth",
                self.depth()
            )

            return task

        except Empty:

            return None

    def requeue(
        self,
        task
    ):

        self.queue.put(
            (
                -task["priority"],
                next(self._sequence),
                task
            )
        )

        metrics.set_gauge(
            "queue_depth",
            self.depth()
        )

    # =====================================

    def depth(self):

        return self.queue.qsize()
