class SeverityEngine:

    def calculate(self, incident):

        severities = [
            a.get("severity", "LOW")
            for a in incident["alerts"]
        ]

        if "HIGH" in severities and len(severities) >= 3:
            return "CRITICAL"

        if "HIGH" in severities:
            return "HIGH"

        return "MEDIUM"
