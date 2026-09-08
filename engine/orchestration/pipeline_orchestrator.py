class PipelineOrchestrator:

    def __init__(self):

        self.stages = []

    # =========================

    def register(self, pipeline):

        self.stages.append(pipeline)

    # =========================

    def execute(self, alert):

        context = {
            "alert": alert
        }

        for stage in self.stages:

            result = stage.run(context)

            if result is False:
                return None

        return context