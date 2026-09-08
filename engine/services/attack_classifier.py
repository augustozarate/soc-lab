class AttackClassifier:

    def classify(self, alert):

        mitre = alert.get("mitre")

        if isinstance(mitre, dict):

            technique_id = mitre.get(
                "technique_id"
            )

            technique = (
                mitre.get("technique")
                or technique_id
            )

            return {
                "tactic": mitre.get("tactic"),
                "technique_id": technique_id,
                "technique": technique
            }

        if alert.get("type") == "UEBA_BRUTE_FORCE":

            return {
                "tactic": "Credential Access",
                "technique_id": "T1110",
                "technique": "Behavioral Brute Force"
            }

        return {
            "tactic": "Unknown",
            "technique_id": None,
            "technique": None
        }