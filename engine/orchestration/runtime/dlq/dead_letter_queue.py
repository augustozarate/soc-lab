import time

class DeadLetterQueue:

    def __init__(
        self,
        store,
        auditor=None,
        metrics=None
    ):

        self.store = store
        self.auditor = auditor
        self.metrics = metrics

    # =========================

    def publish(
        self,
        task,
        error
    ):

        failed_task = {
            "task": task,
            "error": str(error),
            "failed_at": time.time()
        }

        self.store.save(failed_task)

        if self.metrics:
            self.metrics.inc("dead_letter")

        if self.auditor:
            self.auditor(
                "TASK_FAILED",
                failed_task
            )

        print(
            f"[DLQ] stored "
            f"{task['task_id']}"
        )