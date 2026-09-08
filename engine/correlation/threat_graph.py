from collections import defaultdict
import time

class ThreatGraph:

    def __init__(self):
        self.nodes = {}
        self.edges = defaultdict(dict)  # 🔥 evita duplicados

    # =========================
    # NODES
    # =========================
    def add_node(self, node_id, node_type, **attrs):
        if node_id not in self.nodes:
            self.nodes[node_id] = {
                "id": node_id,
                "type": node_type,
                "created": time.time(),
                **attrs
            }

    # =========================
    # EDGES (NO DUPLICATES)
    # =========================
    def add_edge(self, src, dst, relation):

        key = (dst, relation)

        if key not in self.edges[src]:
            self.edges[src][key] = {
                "to": dst,
                "relation": relation,
                "first_seen": time.time(),
                "count": 1
            }
        else:
            self.edges[src][key]["count"] += 1

    # =========================
    # QUERY
    # =========================
    def get_neighbors(self, node_id):
        return list(self.edges.get(node_id, {}).values())

    def find_by_type(self, node_type):
        return [
            n for n in self.nodes.values()
            if n["type"] == node_type
        ]

    def get_incident_context(self, incident_id):

        context = {
            "ips": [],
            "campaigns": [],
            "mitre": []
        }

        # edges desde incidente
        for edge in self.get_neighbors(incident_id):
            if edge["relation"] == "PART_OF":
                context["campaigns"].append(edge["to"])

            elif edge["relation"] == "USES":
                context["mitre"].append(edge["to"])

        # buscar IPs que apuntan al incidente
        for src, edges in self.edges.items():
            for edge in edges.values():
                if edge["to"] == incident_id and edge["relation"] == "TRIGGERS":
                    context["ips"].append(src)

        return context