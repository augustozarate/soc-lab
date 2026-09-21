class SOAREngine:

    def evaluate(self, incident):

        actions = []

        existing = {
            f"{a.get('type')}:{a.get('target')}"
            for a in incident.get(
                "response_actions",
                []
            )
            if a.get("type") and a.get("target")
        }

        severity = incident.get(
            "severity"
        )

        if severity == "CRITICAL":

            ip = incident.get("ip")

            action_id = (
                f"BLOCK_IP:{ip}"
            )

            if (
                ip
                and action_id not in existing
            ):

                actions.append({
                    "type": "BLOCK_IP",
                    "target": ip,
                    "status": "SIMULATED"
                })

        return actions