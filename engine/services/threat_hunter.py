from datetime import datetime, timedelta, timezone
from engine.mitre_hunt_map import MITRE_HUNT_RULES

class ThreatHunter:

    # =========================
    # INIT
    # =========================
    def __init__(self, event_cache):
        self.event_cache = event_cache

    # =========================
    # HUNT LOGIC
    # =========================
    def hunt(self, incident):

        findings = []

        ip = incident.get("ip")
        if not ip:
            return findings

        tactic = incident.get("attack_phase", {}).get("tactic")

        hunt_actions = MITRE_HUNT_RULES.get(tactic, [])

        now = datetime.now(timezone.utc)
        window = now - timedelta(minutes=30)

        for event in self.event_cache:

            ts = event.get("timestamp")
            if not ts:
                continue

            try:
                event_time = datetime.fromisoformat(ts)
            except Exception:
                continue

            if event_time.tzinfo is None:
                event_time = event_time.replace(
                    tzinfo=timezone.utc
                )
            else:
                event_time = event_time.astimezone(
                    timezone.utc
                )

            if event_time < window:
                continue

            if event.get("ip") != ip:
                continue

            if event.get("action") in hunt_actions:

                findings.append({
                    "type": "MITRE_CONTEXT_HUNT",
                    "timestamp": ts,
                    "description": f"Related activity detected for tactic {tactic}",
                    "action": event.get("action")
                })

        return findings
