import json
import os
from datetime import datetime
import threading
import time

class AIMemory:

    def __init__(self, path="data/ai_memory.json"):
        self.path = path
        self.memory = self._load()
        self.lock = threading.Lock()
        self.dirty = False
        self.cache = {}
        self.cache_ttl = 300  # 5 min

        # 🔥 autosave thread
        t = threading.Thread(target=self._autosave_loop, daemon=True)
        t.start()

    def _load(self):
        if os.path.exists(self.path):
            with open(self.path, "r") as f:
                return json.load(f)
        return {
            "incidents": {},
            "ips": {},
            "patterns": []
        }

    def save(self):
        dirpath = os.path.dirname(self.path)

        if dirpath:
            os.makedirs(dirpath, exist_ok=True)

        with self.lock:
            with open(self.path, "w") as f:
                json.dump(self.memory, f, indent=2)

    def _autosave_loop(self):
        while True:
            time.sleep(5)
            if self.dirty:
                self.save()
                self.dirty = False

    def store_incident(self, incident_id, summary):
        if not incident_id:
            return

        self.memory["incidents"][incident_id] = {
            "summary": summary,
            "timestamp": datetime.utcnow().isoformat()
        }

        self.dirty = True

    def update_ip(self, ip, tactic=None, risk=None):
        if ip not in self.memory["ips"]:
            self.memory["ips"][ip] = {
                "seen": 0,
                "tactics": [],
                "max_risk": 0
            }

        data = self.memory["ips"][ip]

        data["seen"] += 1

        if tactic and tactic not in data["tactics"]:
            data["tactics"].append(tactic)

        if risk and risk > data["max_risk"]:
            data["max_risk"] = risk

        self.dirty = True

    def get_ip_context(self, ip):
        return self.memory["ips"].get(ip, {})
    
    def update_from_incident(self, incident, analysis):
        ip = incident.get("ip")

        if not ip:
            return

        entry = self.memory.setdefault(ip, {
            "observations": 0,
            "risk": 0,
            "techniques": []
        })

        entry["observations"] += 1
        entry["risk"] += incident.get("risk_score", 0)

        if analysis.get("technique") not in entry["techniques"]:
            entry["techniques"].append(analysis["technique"])