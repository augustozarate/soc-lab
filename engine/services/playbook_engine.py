class PlaybookEngine:

    def __init__(self):

        self.playbooks = {

            "Credential Access": [
                "BLOCK_IP",
                "NOTIFY_SOC",
                "ENABLE_MFA"
            ],

            "Execution": [
                "ISOLATE_HOST",
                "COLLECT_FORENSICS",
                "NOTIFY_SOC"
            ]
        }

    # =========================================

    def get_playbook(self, incident):

        phase = incident.get(
            "attack_phase",
            {}
        )

        tactic = phase.get(
            "tactic"
        )

        return self.playbooks.get(
            tactic,
            [
                "NOTIFY_SOC"
            ]
        )
