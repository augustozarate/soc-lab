import json
import time
import random
from datetime import datetime


class AdversarySimulator:

    def __init__(self, stream_file):
        self.stream_file = stream_file

        self.attack_chain = [
            ("recon_scan", "LOW"),
            ("login_failed", "HIGH"),
            ("login_failed", "HIGH"),
            ("remote_connection", "MEDIUM"),
            ("admin_login", "CRITICAL"),
            ("scheduled_task_created", "HIGH")
        ]

    def _write_event(self, action, level):

        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "ip": "192.168.20.130",
            "action": action,
            "level": level,
            "source": "adversary_sim"
        }

        with open(self.stream_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")

        print(f"[SIM] Generated → {action}")

    def run_attack(self):

        print("\n[SIM] Starting adversary simulation...\n")

        for action, level in self.attack_chain:
            self._write_event(action, level)
            time.sleep(random.uniform(2, 5))

        print("\n[SIM] Attack simulation finished\n")