import json

class ReplayEngine:

    def __init__(self, scheduler):

        self.scheduler = scheduler

    # =========================

    def replay_file(self, path):

        with open(path, encoding="utf-8") as f:

            for line in f:

                failed = json.loads(line)

                task = failed["task"]

                task["retries"] = 0
                task["state"] = "REPLAYED"

                self.scheduler.requeue(task)

                print(
                    f"[REPLAY] "
                    f"{task['task_id']}"
                )