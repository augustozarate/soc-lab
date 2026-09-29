from collections import defaultdict
from datetime import datetime


class ThreatMemory:

    def __init__(self):
        self.ip_history = defaultdict(list)

    # =========================

    def record(self, ip, tactic):

        self.ip_history[ip].append({
            "tactic": tactic,
            "time": datetime.utcnow()
        })

    # =========================

    def frequency(self, ip):
        return len(self.ip_history[ip])

    # =========================

    def tactics_seen(self, ip):
        return list({
            e["tactic"] for e in self.ip_history[ip]
        })

    # =========================

    def last_seen(self, ip):

        if not self.ip_history[ip]:
            return None

        return self.ip_history[ip][-1]["time"]
