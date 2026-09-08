from collections import defaultdict
import time

ATTACK_FLOW = {
    "Initial Access": ["Execution", "Credential Access"],
    "Execution": ["Persistence"],
    "Credential Access": ["Lateral Movement"],
    "Lateral Movement": ["Privilege Escalation"],
    "Privilege Escalation": ["Persistence"],
    "Persistence": ["Defense Evasion"],
}

class AttackGraph:

    def __init__(self):
        # incident_id -> list of nodes
        self.nodes = defaultdict(list)

        # incident_id -> edges [(from, to)]
        self.edges = defaultdict(list)

        # incident_id -> last tactic
        self.last_seen = {}

    def update(self, incident_id, tactic):

        now = time.time()

        nodes = self.nodes[incident_id]

        # evitar duplicados consecutivos
        if nodes and nodes[-1]["tactic"] == tactic:
            return self.evaluate_progress(incident_id)

        node = {
            "tactic": tactic,
            "time": now
        }

        nodes.append(node)

        # crear edge
        if incident_id in self.last_seen:
            prev = self.last_seen[incident_id]
            self.edges[incident_id].append((prev, tactic))

        self.last_seen[incident_id] = tactic

        return self.evaluate_progress(incident_id)

    # =========================

    def evaluate_progress(self, incident_id):

        nodes = self.nodes[incident_id]
        tactics = [n["tactic"] for n in nodes]

        confidence = min(len(set(tactics)) * 25, 100)

        stage = "RECON"

        if "Credential Access" in tactics:
            stage = "COMPROMISE LIKELY"

        if "Lateral Movement" in tactics:
            stage = "BREACH CONFIRMED"

        if "Privilege Escalation" in tactics:
            stage = "DOMAIN RISK"

        return {
            "nodes": nodes,
            "edges": self.edges[incident_id],
            "stage": stage,
            "confidence": confidence
        }

    # =========================

    def get_graph(self, incident_id):
        return {
            "nodes": self.nodes.get(incident_id, []),
            "edges": self.edges.get(incident_id, [])
        }