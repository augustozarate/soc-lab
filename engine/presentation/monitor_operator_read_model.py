from copy import deepcopy


class MonitorOperatorReadModel:

    DEFAULT_INCIDENT_LIMIT = 10
    MAX_INCIDENT_LIMIT = 100

    def __init__(
        self,
        incident_repository,
        campaign_repository,
    ):
        self.incident_repository = (
            incident_repository
        )

        self.campaign_repository = (
            campaign_repository
        )

    def snapshot(
        self,
        incident_limit=DEFAULT_INCIDENT_LIMIT,
    ):
        bounded_limit = self._limit(
            incident_limit
        )

        incident_summary = (
            self.incident_repository
            .summary_stats()
        )

        campaign_summary = (
            self.campaign_repository
            .summary_stats()
        )

        incidents = (
            self.incident_repository
            .list_recent(
                limit=bounded_limit
            )
        )

        return deepcopy(
            {
                "summary": {
                    "incidents": (
                        incident_summary.get(
                            "incidents",
                            0,
                        )
                    ),
                    "high_critical": (
                        incident_summary.get(
                            "high_critical",
                            0,
                        )
                    ),
                    "campaigns": (
                        campaign_summary.get(
                            "campaigns",
                            0,
                        )
                    ),
                    "max_risk": (
                        campaign_summary.get(
                            "max_risk",
                            0,
                        )
                    ),
                },
                "incidents": incidents,
            }
        )

    @classmethod
    def _limit(
        cls,
        limit,
    ):
        try:
            normalized = int(
                limit
            )
        except (TypeError, ValueError):
            normalized = (
                cls.DEFAULT_INCIDENT_LIMIT
            )

        if normalized <= 0:
            return 0

        return min(
            normalized,
            cls.MAX_INCIDENT_LIMIT,
        )
