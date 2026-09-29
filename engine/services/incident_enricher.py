from engine.storage.entity_memory import EntityMemory

class IncidentEnricher:

    def __init__(self):

        self.memory = EntityMemory()

    def enrich(self, incident):

        incident["tags"] = self._build_tags(incident)

        incident["confidence"] = (
            self._calculate_confidence(incident)
        )

        incident["risk_score"] = (
            self._calculate_risk_score(incident)
        )

        incident["entities"] = (
            self._extract_entities(incident)
        )

        incident["entity_context"] = (
            self._build_entity_context(incident)
        )

        return incident

    # =========================
    # TAGS
    # =========================

    def _build_tags(self, incident):

        tags = set()

        phase = incident.get("attack_phase", {})

        tactic = phase.get("tactic")
        technique = phase.get("technique")

        if tactic:
            tags.add(tactic.lower().replace(" ", "_"))

        if technique:
            tags.add(technique.lower().replace(" ", "_"))

        if incident.get("severity") == "CRITICAL":
            tags.add("critical_threat")

        return sorted(tags)

    # =========================
    # CONFIDENCE
    # =========================

    def _calculate_confidence(self, incident):

        confidence = 0.5

        if incident.get("severity") == "HIGH":
            confidence += 0.2

        if incident.get("severity") == "CRITICAL":
            confidence += 0.3

        if len(incident.get("alerts", [])) >= 5:
            confidence += 0.1

        return round(min(confidence, 1.0), 2)

    # =========================
    # RISK SCORE
    # =========================

    def _calculate_risk_score(self, incident):

        score = 0

        severity = incident.get("severity")

        if severity == "LOW":
            score += 25

        elif severity == "MEDIUM":
            score += 50

        elif severity == "HIGH":
            score += 75

        elif severity == "CRITICAL":
            score += 95

        score += min(
            len(incident.get("alerts", [])) * 2,
            10
        )

        return min(score, 100)

    # =========================
    # ENTITY EXTRACTION
    # =========================

    def _extract_entities(self, incident):

        entities = []

        if incident.get("ip"):
            entities.append({
                "type": "ip",
                "value": incident["ip"]
            })

        return entities

    # =========================
    # ENTITY CONTEXT
    # =========================

    def _build_entity_context(self, incident):

        context = {}

        for entity in incident.get("entities", []):

            entity_type = entity["type"]
            value = entity["value"]

            memory = self.memory.remember(
                entity_type,
                value,
                incident
            )

            key = f"{entity_type}:{value}"

            context[key] = {
                "seen": memory["seen"],
                "reputation": memory["reputation"],
                "first_seen": memory["first_seen"],
                "last_seen": memory["last_seen"],
                "incidents": memory["incidents"],
            }

        return context
