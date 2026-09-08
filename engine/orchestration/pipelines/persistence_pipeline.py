class PersistencePipeline:

    def __init__(
        self,
        incident_repository,
        campaign_repository
    ):

        self.incident_repository = incident_repository
        self.campaign_repository = campaign_repository

    def run(self, context):

        incident = context.get("incident")

        if incident:
            self.incident_repository.save(
                incident
            )

        campaign = context.get("campaign")

        if campaign:
            self.campaign_repository.save(
                campaign
            )

        return True