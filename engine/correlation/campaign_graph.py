class CampaignGraph:
    def __init__(self):
        self.nodes = {}   # id -> type
        self.edges = []   # (src, dst, relation)

    # =========================
    # ADD NODES
    # =========================

    def add_node(self, node_id, node_type):
        if node_id not in self.nodes:
            self.nodes[node_id] = node_type

    # =========================
    # RELATIONS
    # =========================

    def link_campaign_incident(self, cid, iid):
        self.edges.append((cid, iid, "HAS_INCIDENT"))

    def link_campaign_ip(self, cid, ip):
        self.edges.append((cid, ip, "USES_IP"))

    def link_campaign_technique(self, cid, tech):
        self.edges.append((cid, tech, "USES_TECHNIQUE"))

    # =========================
    # BUILD FROM DATA
    # =========================

    def build_from_campaign(self, campaign, incident_manager):

        cid = campaign["id"]
        self.add_node(cid, "CAMPAIGN")

        # incidents
        for iid in campaign.get("incidents", []):
            self.add_node(iid, "INCIDENT")
            self.link_campaign_incident(cid, iid)

            inc = incident_manager.get(iid)

            if not inc:
                continue

            # IPs
            ip = inc.get("ip")
            if ip:
                self.add_node(ip, "IP")
                self.link_campaign_ip(cid, ip)

            # MITRE
            mitre = inc.get("mitre") or {}
            tech = mitre.get("technique_id")

            if tech:
                self.add_node(tech, "MITRE")
                self.link_campaign_technique(cid, tech)

    # =========================
    # VIEW
    # =========================

    def get_view(self, cid):
        return {
            "nodes": self.nodes,
            "edges": [e for e in self.edges if cid in e]
        }