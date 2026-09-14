import time
from collections import defaultdict, deque

from engine.cli.console_io import safe_print


class DetectionEngine:

    def __init__(self, rules):

        self.rules = rules

        self.matches = defaultdict(deque)

        safe_print(
            f"[RULE ENGINE] Loaded "
            f"{len(rules)} rules"
        )

    # =====================================

    def evaluate(self, event):

        alerts = []

        for rule in self.rules:

            match = rule.get("match")

            if not isinstance(match, dict):

                safe_print(
                    "[RULE ERROR] "
                    "Rule missing match section: "
                    f"{rule.get('id', 'unknown')}"
                )

                continue

            rule_id = rule.get("id")

            match_text = match.get(
                "message_contains"
            )

            if not rule_id or not match_text:

                safe_print(
                    "[RULE ERROR] "
                    "Invalid rule: "
                    f"{rule_id or 'unknown'}"
                )

                continue

            message = event.get(
                "message",
                ""
            )

            if match_text not in message:
                continue

            threshold = max(
                1,
                int(
                    match.get(
                        "threshold",
                        1
                    )
                )
            )

            window_seconds = max(
                1,
                int(
                    match.get(
                        "window_seconds",
                        60
                    )
                )
            )

            ip = event.get("ip")

            key = (
                rule_id,
                ip
            )

            now = time.monotonic()

            bucket = self.matches[key]

            cutoff = (
                now - window_seconds
            )

            while (
                bucket
                and bucket[0] < cutoff
            ):
                bucket.popleft()

            bucket.append(now)

            if len(bucket) < threshold:
                continue

            alert = {
                "rule_id": rule_id,
                "type": rule_id,

                "severity": rule.get(
                    "severity",
                    "MEDIUM"
                ),

                "ip": ip,
                "message": message,

                "match_count": len(bucket),

                "window_seconds": (
                    window_seconds
                ),

                "source_record_id": event.get(
                    "record_id"
                ),

                "source_event_id": event.get(
                    "event_id"
                )
            }

            alerts.append(alert)

            # Start a new detection group after
            # this alert to prevent alert storms.
            bucket.clear()

        return alerts

    # =====================================

    def update_rules(self, new_rules):

        self.rules = new_rules

        # Old counters may no longer correspond
        # to the newly loaded rule semantics.
        self.matches.clear()

        safe_print(
            f"[RULE ENGINE] Hot reloaded "
            f"{len(new_rules)} rules"
        )