from collections import OrderedDict

MITRE_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact"
]


class AttackTimelineBuilder:

    def build(self, incident):

        tactics_seen = set()

        for alert in incident.get("alerts", []):
            mitre = alert.get("mitre")
            if mitre:
                tactics_seen.add(mitre.get("tactic"))

        ordered = [
            t for t in MITRE_ORDER if t in tactics_seen
        ]

        stage = self._calculate_stage(ordered)

        return {
            "progression": ordered,
            "stage": stage,
            "confidence": min(100, len(ordered) * 20)
        }

    def _calculate_stage(self, tactics):

        if not tactics:
            return "UNKNOWN"

        if "Impact" in tactics:
            return "BREACH"

        if "Lateral Movement" in tactics:
            return "ACTIVE INTRUSION"

        if "Credential Access" in tactics:
            return "COMPROMISE LIKELY"

        if "Initial Access" in tactics:
            return "INITIAL COMPROMISE"

        return "RECONNAISSANCE"