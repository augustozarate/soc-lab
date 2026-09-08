from engine.services.playbook_engine import (
    PlaybookEngine
)


class ResponsePolicyEngine:

    def __init__(self):

        self.playbooks = PlaybookEngine()

    # =========================================
    # POLICY EVALUATION
    # =========================================

    def evaluate(self, incident):

        playbook = (
            self.playbooks.get_playbook(
                incident
            )
        )

        actions = []

        for step in playbook:

            action = self._build_action(
                step,
                incident
            )

            if action:
                actions.append(
                    action
                )

        return actions

    # =========================================
    # ACTION BUILDING
    # =========================================

    def _build_action(
        self,
        step,
        incident
    ):

        if step == "BLOCK_IP":

            ip = incident.get("ip")

            if not ip:
                return None

            return {
                "type": "BLOCK_IP",
                "target": ip,
                "status": "PENDING",
                "reason": (
                    "Response playbook"
                )
            }

        if step == "NOTIFY_SOC":

            return {
                "type": "NOTIFY_SOC",
                "target": "SOC_TEAM",
                "status": "PENDING",
                "reason": (
                    "Incident response notification"
                )
            }

        if step == "ENABLE_MFA":

            return {
                "type": "ENABLE_MFA",
                "target": (
                    incident.get("user")
                    or incident.get("ip")
                ),
                "status": "PENDING",
                "reason": (
                    "Credential Access mitigation"
                )
            }

        if step == "ISOLATE_HOST":

            host = incident.get("host")

            if not host:
                return None

            return {
                "type": "ISOLATE_HOST",
                "target": host,
                "status": "PENDING",
                "reason": (
                    "Execution containment"
                )
            }

        if step == "COLLECT_FORENSICS":

            return {
                "type": "COLLECT_FORENSICS",
                "target": incident.get(
                    "id"
                ),
                "status": "PENDING",
                "reason": (
                    "Evidence collection"
                )
            }

        return None