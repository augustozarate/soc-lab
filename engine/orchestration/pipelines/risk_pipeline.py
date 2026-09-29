class RiskPipeline:

    def __init__(
        self,
        risk_engine,
        threat_memory,
        event_bus
    ):

        self.risk_engine = risk_engine
        self.threat_memory = threat_memory
        self.event_bus = event_bus

    # =========================

    def run(self, context):

        risk = self.risk_engine.calculate(
            context["alert"],
            self.threat_memory,
            context["incident"]
        )

        context["risk"] = risk

        context["incident"]["risk_score"] = risk

        if risk >= 80:

            self.event_bus.emit(
                "risk_high",
                context
            )

        return True