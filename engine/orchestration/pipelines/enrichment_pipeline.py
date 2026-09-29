class EnrichmentPipeline:

    def __init__(
        self,
        threat_intel,
        entity_resolver,
        threat_memory
    ):

        self.threat_intel = threat_intel
        self.entity_resolver = entity_resolver
        self.threat_memory = threat_memory

    # =========================

    def run(self, context):

        alert = context["alert"]
        incident = context["incident"]

        ip = alert.get("ip")

        if ip:

            intel = self.threat_intel.check_ip(ip)

            incident["threat_intel"] = intel
            alert["threat_intel"] = intel

        entities = self.entity_resolver.extract(alert)

        incident["entities"] = entities

        # Threat Memory
        if ip and "mitre" in alert:

            tactic = alert["mitre"].get("tactic")

            if tactic:
                self.threat_memory.record(
                    ip,
                    tactic
                )

        return True
