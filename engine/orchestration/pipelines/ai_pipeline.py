class AIPipeline:

    def __init__(
        self,
        ai_analyst,
        threat_graph
    ):

        self.ai_analyst = ai_analyst
        self.threat_graph = threat_graph

    # =========================

    def run(self, context):

        analysis = self.ai_analyst.analyze(
            context["incident"],
            campaign=context.get("campaign"),
            graph=self.threat_graph
        )

        context["incident"]["ai_analysis"] = analysis

        return True