class HuntingPipeline:

    def __init__(
        self,
        hunter,
        threat_graph,
        auditor
    ):

        self.hunter = hunter
        self.threat_graph = threat_graph
        self.auditor = auditor

    # =========================

    def run(self, context):

        incident = context["incident"]

        results = self.hunter.hunt(incident)

        if results:

            incident["hunt_findings"] = results

            self.auditor(
                "HUNT_FINDINGS",
                results
            )

        correlation = context.get(
            "correlation",
            {}
        )

        cid = correlation.get("campaign_id")

        ip = incident.get("ip")

        if ip and cid:

            self.threat_graph.add_edge(
                ip,
                cid,
                "SEEN_IN"
            )

        return True
