import uuid
from datetime import datetime

from engine.services.severity_engine import SeverityEngine
from engine.services.attack_classifier import AttackClassifier
from engine.services.incident_lifecycle import IncidentLifecycle
from engine.services.incident_enricher import IncidentEnricher

from engine.analysis.attack_timeline import AttackTimelineBuilder
from engine.analysis.attack_predictor import AttackPredictor

from engine.models.incident_state import IncidentState


class IncidentManager:

    def __init__(self):

        # =====================================
        # STORAGE
        # =====================================

        self.incidents = {}
        self.by_id = {}

        # =====================================
        # SERVICES
        # =====================================

        self.severity_engine = SeverityEngine()
        self.attack_classifier = AttackClassifier()

        # =====================================
        # ANALYSIS
        # =====================================

        self.timeline_builder = AttackTimelineBuilder()
        self.predictor = AttackPredictor()

        # =====================================
        # LIFECYCLE
        # =====================================

        self.lifecycle = IncidentLifecycle()

        # =====================================
        # ENRICHMENT
        # =====================================

        self.enricher = IncidentEnricher()

    # =========================================
    # PUBLIC ACCESSORS
    # =========================================

    def get(self, incident_id):

        return self.by_id.get(
            incident_id
        )

    # =========================================
    # INTERNAL HELPERS
    # =========================================

    def _generate_id(self):

        return str(
            uuid.uuid4()
        )[:8]

    def _now(self):

        return datetime.utcnow().isoformat()

    def _alert_signature(self, alert):

        return (
            alert.get("rule_id")
            or alert.get("type"),

            alert.get("ip"),

            alert.get(
                "mitre",
                {}
            ).get(
                "technique_id"
            ),
        )

    # =========================================
    # CREATE / UPDATE
    # =========================================

    def create_or_update(self, alert):

        key = alert.get("ip")

        # =====================================
        # UPDATE EXISTING INCIDENT
        # =====================================

        if key in self.incidents:

            incident = self.incidents[key]

            sig = self._alert_signature(
                alert
            )

            existing = {
                self._alert_signature(a)
                for a in incident.get(
                    "alerts",
                    []
                )
            }

            if sig not in existing:

                incident.setdefault(
                    "alerts",
                    []
                ).append(
                    alert
                )

            now = self._now()

            incident.setdefault(
                "timeline",
                []
            ).append({
                "time": now,
                "event": (
                    alert.get("type")
                    or alert.get("rule_id")
                )
            })

            # Limitar historial en memoria
            if len(
                incident["timeline"]
            ) > 100:

                incident[
                    "timeline"
                ].pop(0)

            incident["updated"] = now
            incident["last_seen"] = now

            # Recalcular estado derivado
            self._recalculate_incident(
                incident
            )

            # Actualizar análisis temporal
            incident["attack_story"] = (
                self.timeline_builder.build(
                    incident
                )
            )

            incident["predictions"] = (
                self.predictor.predict(
                    incident
                )
            )

            return incident, False

        # =====================================
        # CREATE NEW INCIDENT
        # =====================================

        now = self._now()

        incident = {
            "id": self._generate_id(),
            "ip": key,
            "created": now,
            "updated": now,
            "last_seen": now,

            "severity": alert.get(
                "severity",
                "LOW"
            ),

            "status": IncidentState.NEW,

            "alerts": [
                alert
            ],

            "timeline": [
                {
                    "time": now,
                    "event": (
                        alert.get("type")
                        or alert.get("rule_id")
                    )
                }
            ],

            "attack_phase": (
                self.attack_classifier.classify(
                    alert
                )
            ),

            "response_actions": []
        }

        self._recalculate_incident(
            incident
        )

        incident["attack_story"] = (
            self.timeline_builder.build(
                incident
            )
        )

        incident["predictions"] = (
            self.predictor.predict(
                incident
            )
        )

        self.incidents[key] = incident

        self.by_id[
            incident["id"]
        ] = incident

        return incident, True

    # =========================================
    # INCIDENT STATE CALCULATION
    # =========================================

    def _recalculate_incident(
        self,
        incident
    ):

        incident["severity"] = (
            self.severity_engine.calculate(
                incident
            )
        )

        self.lifecycle.process(
            incident
        )

        self.enricher.enrich(
            incident
        )