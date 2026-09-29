import uuid
import time

class TaskContext(dict):

    def __init__(
        self,
        event_type,
        payload,
        priority=50
    ):

        super().__init__()

        self["task_id"] = str(uuid.uuid4())

        self["event_type"] = event_type

        self["payload"] = payload

        self["priority"] = priority

        self["created_at"] = time.time()

        self["retries"] = 0

        self["state"] = "PENDING"
