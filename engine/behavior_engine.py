from collections import defaultdict, deque
import time


class BehaviorEngine:

    def __init__(
        self,
        threshold=5,
        window_seconds=60
    ):

        self.threshold = threshold
        self.window_seconds = window_seconds

        self.activity = defaultdict(deque)

    # =====================================

    def analyze(self, event):

        ip = event.get("ip")

        if not ip:
            return []

        # Only authentication-failure-like events
        if not self._is_failed_login(event):
            return []

        now = time.monotonic()

        bucket = self.activity[ip]

        cutoff = (
            now - self.window_seconds
        )

        while (
            bucket
            and bucket[0] < cutoff
        ):
            bucket.popleft()

        bucket.append(now)

        if len(bucket) < self.threshold:
            return []

        count = len(bucket)

        bucket.clear()

        return [
            {
                "type": "UEBA_BRUTE_FORCE",
                "ip": ip,
                "count": count,
                "severity": "HIGH",

                "source_record_id": event.get(
                    "record_id"
                ),

                "source_event_id": event.get(
                    "event_id"
                )
            }
        ]

    # =====================================

    def _is_failed_login(self, event):

        message = str(
            event.get("message", "")
        ).upper()

        event_type = str(
            event.get("type", "")
        ).lower()

        action = str(
            event.get("action", "")
        ).lower()

        return (
            "FAILED LOGIN" in message
            or event_type == "login_failed"
            or action == "login_failed"
        )