from pathlib import Path
import json


class FailedTaskStore:

    def __init__(self, path):

        self.path = Path(path)

        self.path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

    def save(self, failed_task):

        with self.path.open(
            "a",
            encoding="utf-8"
        ) as f:

            f.write(
                json.dumps(
                    failed_task,
                    ensure_ascii=False
                )
                + "\n"
            )

            f.flush()