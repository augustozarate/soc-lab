from copy import deepcopy


class PersistencePipeline:

    def __init__(
        self,
        incident_repository,
        campaign_repository,
        event_bus=None,
    ):

        self.incident_repository = (
            incident_repository
        )

        self.campaign_repository = (
            campaign_repository
        )

        self.event_bus = event_bus

    def run(
        self,
        context,
    ):

        incident = context.get(
            "incident"
        )

        if incident:

            self.incident_repository.save(
                incident
            )

        campaign = context.get(
            "campaign"
        )

        if campaign:

            self.campaign_repository.save(
                campaign
            )

        # Notification intent is emitted only
        # after persistence completed
        # successfully.
        if (
            incident
            and self.event_bus
        ):

            self.event_bus.emit(
                "incident_persisted",
                {
                    "incident": deepcopy(
                        incident
                    )
                },
            )

        return True
