class CorrelationPipeline:

    def __init__(
        self,
        threat_graph,
        entity_resolver,
        campaign_tracker,
        campaign_graph,
        incident_manager
    ):

        self.threat_graph = threat_graph
        self.entity_resolver = entity_resolver
        self.campaign_tracker = campaign_tracker
        self.campaign_graph = campaign_graph
        self.incident_manager = incident_manager

    # =========================

    def run(self, context):

        alert = context["alert"]
        incident = context["incident"]

        ip = alert.get("ip")
        iid = incident["id"]

        # =====================================
        # INCIDENT NODE
        # =====================================

        self.threat_graph.add_node(
            iid,
            "INCIDENT"
        )

        # =====================================
        # IP CORRELATION
        # =====================================

        if ip:

            self.threat_graph.add_node(
                ip,
                "IP"
            )

            self.threat_graph.add_edge(
                ip,
                iid,
                "TRIGGERS"
            )

        # =====================================
        # MITRE CORRELATION
        # =====================================

        attack_phase = incident.get(
            "attack_phase",
            {}
        )

        technique_id = (
            attack_phase.get("technique_id")
            or attack_phase.get("technique")
        )

        if technique_id:

            self.threat_graph.add_node(
                technique_id,
                "MITRE_TECHNIQUE"
            )

            self.threat_graph.add_edge(
                iid,
                technique_id,
                "USES"
            )

        entities = self.entity_resolver.extract(
            alert
        )

        incident["entities"] = entities

        campaign, is_new = (
            self.campaign_tracker.correlate(
                incident
            )
        )

        cid = campaign["id"]

        self.threat_graph.add_node(
            cid,
            "CAMPAIGN"
        )

        self.threat_graph.add_edge(
            iid,
            cid,
            "PART_OF"
        )

        incident["campaign_id"] = cid

        self.campaign_graph.build_from_campaign(
            campaign,
            self.incident_manager
        )

        context["campaign"] = campaign

        context["correlation"] = {
            "campaign": campaign,
            "campaign_id": cid,
            "is_new_campaign": is_new
        }

        return True