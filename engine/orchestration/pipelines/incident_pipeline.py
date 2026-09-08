import time


class IncidentPipeline:

    def __init__(
        self,
        incident_manager,
        event_bus
    ):

        self.incident_manager = incident_manager
        self.event_bus = event_bus

        self.recent_alerts = {}

    # =========================

    def run(self, context):

        alert = context["alert"]

        # =====================================
        # DEDUPLICATION
        # =====================================

        if self._is_duplicate(alert):
            return False

        # =====================================
        # CREATE / UPDATE INCIDENT
        # =====================================

        incident, is_new = (
            self.incident_manager.create_or_update(
                alert
            )
        )

        if not incident:
            return False

        # =====================================
        # UPDATE CONTEXT
        # =====================================

        context["incident"] = incident
        context["is_new"] = is_new

        # =====================================
        # DOMAIN EVENT
        # =====================================

        if is_new:

            self.event_bus.emit(
                "incident_created",
                context
            )

        else:

            self.event_bus.emit(
                "incident_updated",
                context
            )

        return True

    # =========================

    def _is_duplicate(self, alert):

        now = time.time()

        key = (
            alert.get("rule_id") or alert.get("type"),
            alert.get("ip"),
            alert.get("mitre", {}).get("technique_id"),
        )

        self.recent_alerts = {
            k: t
            for k, t in self.recent_alerts.items()
            if now - t < 10
        }

        if key in self.recent_alerts:
            return True

        self.recent_alerts[key] = now

        return False