"""
Attack Predictor Engine
-----------------------
Predicts likely attacker next steps based on MITRE ATT&CK progression.
"""

from collections import Counter


class AttackPredictor:

    def __init__(self):

        # Simplified MITRE progression model
        # (real SOCs usan grafos enormes)
        self.attack_graph = {

            "Initial Access": [
                ("Execution", 0.6),
                ("Credential Access", 0.4),
            ],

            "Credential Access": [
                ("Lateral Movement", 0.65),
                ("Privilege Escalation", 0.45),
                ("Persistence", 0.30),
            ],

            "Execution": [
                ("Persistence", 0.5),
                ("Privilege Escalation", 0.4),
            ],

            "Lateral Movement": [
                ("Privilege Escalation", 0.7),
                ("Collection", 0.5),
            ],

            "Privilege Escalation": [
                ("Persistence", 0.6),
                ("Defense Evasion", 0.5),
            ],

            "Persistence": [
                ("Command and Control", 0.7),
            ],

            "Command and Control": [
                ("Exfiltration", 0.8),
                ("Impact", 0.6),
            ],
        }

    # ======================================
    # PUBLIC API
    # ======================================

    def predict(self, incident):

        story = incident.get("attack_story", {})
        progression = story.get("progression", [])

        if not progression:
            return []

        last_stage = progression[-1]

        candidates = self.attack_graph.get(last_stage, [])

        predictions = []

        for tactic, probability in candidates:
            predictions.append({
                "next_tactic": tactic,
                "probability": int(probability * 100)
            })

        return sorted(
            predictions,
            key=lambda x: x["probability"],
            reverse=True
        )
