import uuid
from datetime import datetime


class PlaybookRuntime:

    def __init__(self, response_engine):

        self.response_engine = response_engine

    # =========================

    def _now(self):

        return datetime.utcnow().isoformat()

    # =========================

    def _generate_execution_id(self):

        return str(uuid.uuid4())[:8]

    # =========================

    def execute(
        self,
        actions,
        stop_on_failure=True
    ):

        execution = {
            "execution_id": (
                self._generate_execution_id()
            ),
            "started_at": self._now(),
            "status": "RUNNING",
            "steps": [],
            "completed_steps": 0,
            "failed_steps": 0,
        }

        for index, action in enumerate(actions):

            step_result = (
                self.response_engine.execute(action)
            )

            execution["steps"].append({
                "step": index + 1,
                "action": action.get("type"),
                "target": action.get("target"),
                "status": step_result.get(
                    "status",
                    "UNKNOWN"
                ),
                "result": step_result,
                "executed_at": self._now()
            })

            if (
                step_result.get("status")
                == "FAILED"
            ):

                execution["failed_steps"] += 1

                if stop_on_failure:

                    execution["status"] = "FAILED"
                    execution["finished_at"] = (
                        self._now()
                    )

                    return execution

            else:

                execution["completed_steps"] += 1

        execution["status"] = "COMPLETED"
        execution["finished_at"] = self._now()

        return execution