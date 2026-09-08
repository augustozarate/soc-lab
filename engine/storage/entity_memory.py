from datetime import datetime


class EntityMemory:

    def __init__(self):

        self.entities = {}

    # =========================
    # PUBLIC API
    # =========================

    def remember(self, entity_type, value, incident):

        key = self._build_key(entity_type, value)

        if key not in self.entities:
            self.entities[key] = self._new_entity(
                entity_type,
                value
            )

        entity = self.entities[key]

        entity["seen"] += 1
        entity["last_seen"] = self._now()

        incident_id = incident.get("id")

        if incident_id and incident_id not in entity["incidents"]:
            entity["incidents"].append(incident_id)

        severity = incident.get("severity")

        if severity:
            entity["severity_history"].append(severity)

        self._update_reputation(entity)

        return entity

    def get(self, entity_type, value):

        key = self._build_key(entity_type, value)

        return self.entities.get(key)

    # =========================
    # INTERNALS
    # =========================

    def _new_entity(self, entity_type, value):

        now = self._now()

        return {
            "type": entity_type,
            "value": value,
            "seen": 0,
            "first_seen": now,
            "last_seen": now,
            "incidents": [],
            "severity_history": [],
            "reputation": "unknown",
        }

    def _update_reputation(self, entity):

        criticals = entity["severity_history"].count("CRITICAL")
        highs = entity["severity_history"].count("HIGH")

        if criticals >= 3:
            entity["reputation"] = "malicious"

        elif highs >= 3:
            entity["reputation"] = "suspicious"

        else:
            entity["reputation"] = "unknown"

    def _build_key(self, entity_type, value):

        return f"{entity_type}:{value}"

    def _now(self):

        return datetime.utcnow().isoformat()