from collections import defaultdict
from datetime import datetime

class Metrics:

    def __init__(self):
        self.counters = defaultdict(int)
        self.start_time = datetime.utcnow()

    def inc(self, metric):
        self.counters[metric] += 1

    def snapshot(self):
        uptime = (datetime.utcnow() - self.start_time).seconds

        return {
            "uptime_seconds": uptime,
            "metrics": dict(self.counters)
        }


metrics = Metrics()