import time


class RetryPolicy:

    def __init__(
        self,
        scheduler,
        dead_letter_queue,
        max_retries=3,
        backoff=2
    ):

        self.scheduler = scheduler
        self.max_retries = max_retries
        self.backoff = backoff
        self.dead_letter_queue = dead_letter_queue

    def handle_failure(
        self,
        task,
        error
    ):

        task["retries"] += 1
        task["last_error"] = str(error)

        print(
            f"[RETRY] "
            f"task={task['task_id']} "
            f"retry={task['retries']} "
            f"error={error}"
        )

        if task["retries"] > self.max_retries:

            task["state"] = "FAILED"

            print(
                f"[DEAD LETTER] "
                f"{task['task_id']}"
            )

            self.dead_letter_queue.publish(
                task,
                error
            )

            return False

        delay = (
            self.backoff
            ** task["retries"]
        )

        time.sleep(delay)

        task["state"] = "RETRYING"

        self.scheduler.requeue(
            task
        )

        return True