from datetime import datetime
from engine.models.incident_state import IncidentState


class IncidentLifecycle:

    def process(self, incident):

        current = incident.get("status")

        new_status = self._determine_status(incident)

        if not new_status:
            return incident

        if current == new_status:
            return incident

        incident["status"] = new_status

        incident.setdefault("status_history", []).append({
            "from": current,
            "to": new_status,
            "time": self._now()
        })

        return incident

    # =========================
    # STATE DECISION
    # =========================

    def _determine_status(self, incident):

        severity = incident.get("severity")
        alert_count = len(incident.get("alerts", []))

        if severity == "CRITICAL":
            return IncidentState.ESCALATED

        if alert_count >= 5:
            return IncidentState.INVESTIGATING

        return IncidentState.NEW

    # =========================
    # TIME
    # =========================

    def _now(self):
        return datetime.utcnow().isoformat()