from datetime import datetime, timedelta

class SuppressionEngine:

    def __init__(self):
        self.cache = {}
        self.cache_ttl = 300  # 5 min
        self.suppression_window = timedelta(seconds=30)

    def allow(self, alert):

        key = self._build_key(alert)
        now = datetime.utcnow()

        if key in self.cache:
            last_seen = self.cache[key]

            if now - last_seen < self.suppression_window:
                return False  # suppress alert

        self.cache[key] = now
        return True

    def _build_key(self, alert):

        if "rule_id" in alert:
            return f"RULE:{alert['rule_id']}:{alert.get('ip')}"

        if "type" in alert:
            return f"UEBA:{alert['type']}:{alert.get('ip')}"

        return str(alert)