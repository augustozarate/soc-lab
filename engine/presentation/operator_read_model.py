from copy import deepcopy


class OperatorReadModel:

    def __init__(
        self,
        incident_repository,
        campaign_repository,
        case_manager,
        event_cache,
    ):
        self.incident_repository = incident_repository
        self.campaign_repository = campaign_repository
        self.case_manager = case_manager
        self.event_cache = event_cache

    def incidents(self):
        return deepcopy(
            self.incident_repository.list_all()
        )

    def campaigns(self):
        return deepcopy(
            self.campaign_repository.list_all()
        )

    def cases(self):
        return deepcopy(
            self.case_manager.list_cases()
        )

    def recent_events(self, limit=10):
        if limit <= 0:
            return []

        return deepcopy(
            self.event_cache[-limit:]
        )

    def snapshot(
        self,
        recent_event_limit=10,
    ):
        return {
            "summary": self.summary(),
            "incidents": self.incidents(),
            "campaigns": self.campaigns(),
            "cases": self.cases(),
            "recent_events": self.recent_events(
                recent_event_limit
            ),
        }

    def summary(self):
        incidents = self.incidents()
        campaigns = self.campaigns()

        high_critical = sum(
            1
            for incident in incidents
            if str(
                incident.get(
                    "severity",
                    "",
                )
            ).upper()
            in {
                "HIGH",
                "CRITICAL",
            }
        )

        risks = [
            self._number(
                campaign.get(
                    "risk",
                    0,
                )
            )
            for campaign in campaigns
        ]

        return {
            "incidents": len(incidents),
            "high_critical": high_critical,
            "campaigns": len(campaigns),
            "max_risk": (
                max(risks)
                if risks
                else 0
            ),
        }

    @staticmethod
    def _number(value):
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0
