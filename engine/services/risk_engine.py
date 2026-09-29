class RiskEngine:

    # =========================
    # BASE RISK (tu lógica actual)
    # =========================
    def base_score(self, alert):

        score = 0

        severity_map = {
            "LOW": 10,
            "MEDIUM": 25,
            "HIGH": 40,
            "CRITICAL": 60
        }

        score += severity_map.get(alert.get("severity"), 0)

        intel = alert.get("threat_intel", {})

        if intel.get("reputation") == "malicious":
            score += 40
        elif intel.get("reputation") == "suspicious":
            score += 20

        if alert.get("type", "").startswith("UEBA"):
            score += 25

        return min(score, 100)

    # =========================
    # ADAPTIVE RISK (nuevo)
    # =========================
    def adaptive_score(self, alert, threat_memory):

        base = self.base_score(alert)

        ip = alert.get("ip")
        if not ip:
            return base

        frequency = threat_memory.frequency(ip)

        # aprendizaje progresivo
        adaptive_bonus = min(frequency * 3, 20)

        return min(base + adaptive_bonus, 100)

    # =========================
    # COMPATIBILITY ENTRYPOINT
    # =========================
    def calculate(self, alert, threat_memory, incident=None):

        score = 0

        # Base severity
        severity = alert.get("severity", "LOW")

        if severity == "HIGH":
            score += 50
        elif severity == "MEDIUM":
            score += 30
        else:
            score += 10

        # Threat intel
        intel = alert.get("threat_intel", {})
        if intel.get("reputation") == "suspicious":
            score += 20

        # Threat memory (repetición de tácticas)
        ip = alert.get("ip")
        if ip:
            frequency = threat_memory.frequency(ip)

            if frequency > 3:
                score += 15

        # 🆕 CONTEXTO DEL INCIDENTE
        if incident:
            alert_count = len(incident.get("alerts", []))

            if alert_count > 5:
                score += 15

            if incident.get("severity") == "CRITICAL":
                score += 20

        if incident and incident.get("ai_analysis"):
            confidence = incident["ai_analysis"].get("confidence", 0)
            incident["risk_score"] += int(confidence * 10)

        return min(score, 100)
