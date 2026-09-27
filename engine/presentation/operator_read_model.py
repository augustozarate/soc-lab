from copy import deepcopy


class OperatorReadModel:

    DEFAULT_INCIDENT_LIMIT = 20
    DEFAULT_CAMPAIGN_LIMIT = 20
    DEFAULT_CASE_LIMIT = 20

    MAX_INCIDENT_LIMIT = 100
    MAX_CAMPAIGN_LIMIT = 100
    MAX_CASE_LIMIT = 100

    def __init__(
        self,
        incident_repository,
        campaign_repository,
        case_manager,
        event_cache,
    ):
        self.incident_repository = (
            incident_repository
        )

        self.campaign_repository = (
            campaign_repository
        )

        self.case_manager = (
            case_manager
        )

        self.event_cache = event_cache

    def incidents(
        self,
        limit=DEFAULT_INCIDENT_LIMIT,
    ):
        bounded_limit = self._bounded_limit(
            limit,
            default=self.DEFAULT_INCIDENT_LIMIT,
            maximum=self.MAX_INCIDENT_LIMIT,
        )

        rows = (
            self.incident_repository
            .list_recent_summaries(
                limit=bounded_limit
            )
        )

        return deepcopy(
            rows
            if isinstance(
                rows,
                list,
            )
            else []
        )

    def campaigns(
        self,
        limit=DEFAULT_CAMPAIGN_LIMIT,
    ):
        bounded_limit = self._bounded_limit(
            limit,
            default=self.DEFAULT_CAMPAIGN_LIMIT,
            maximum=self.MAX_CAMPAIGN_LIMIT,
        )

        rows = (
            self.campaign_repository
            .list_recent(
                limit=bounded_limit
            )
        )

        return deepcopy(
            rows
            if isinstance(
                rows,
                list,
            )
            else []
        )

    def cases(
        self,
        limit=DEFAULT_CASE_LIMIT,
    ):
        bounded_limit = self._bounded_limit(
            limit,
            default=self.DEFAULT_CASE_LIMIT,
            maximum=self.MAX_CASE_LIMIT,
        )

        rows = (
            self.case_manager
            .list_recent(
                limit=bounded_limit
            )
        )

        return deepcopy(
            rows
            if isinstance(
                rows,
                list,
            )
            else []
        )

    def recent_events(
        self,
        limit=10,
    ):
        if limit <= 0:
            return []

        return deepcopy(
            self.event_cache[
                -limit:
            ]
        )

    def snapshot(
        self,
        recent_event_limit=10,
        incident_limit=DEFAULT_INCIDENT_LIMIT,
        campaign_limit=DEFAULT_CAMPAIGN_LIMIT,
        case_limit=DEFAULT_CASE_LIMIT,
    ):
        return {
            "summary": self.summary(),
            "incidents": self.incidents(
                incident_limit
            ),
            "campaigns": self.campaigns(
                campaign_limit
            ),
            "cases": self.cases(
                case_limit
            ),
            "recent_events": self.recent_events(
                recent_event_limit
            ),
        }

    def summary(
        self,
    ):
        incident_summary = (
            self.incident_repository
            .summary_stats()
        )

        campaign_summary = (
            self.campaign_repository
            .summary_stats()
        )

        incident_summary = (
            incident_summary
            if isinstance(
                incident_summary,
                dict,
            )
            else {}
        )

        campaign_summary = (
            campaign_summary
            if isinstance(
                campaign_summary,
                dict,
            )
            else {}
        )

        return {
            "incidents": self._integer(
                incident_summary.get(
                    "incidents",
                    0,
                )
            ),
            "high_critical": self._integer(
                incident_summary.get(
                    "high_critical",
                    0,
                )
            ),
            "campaigns": self._integer(
                campaign_summary.get(
                    "campaigns",
                    0,
                )
            ),
            "max_risk": self._number(
                campaign_summary.get(
                    "max_risk",
                    0,
                )
            ),
        }

    @staticmethod
    def _bounded_limit(
        value,
        default,
        maximum,
    ):
        try:
            normalized = int(
                value
            )

        except (
            TypeError,
            ValueError,
        ):
            normalized = default

        if normalized <= 0:
            return 0

        return min(
            normalized,
            maximum,
        )

    @staticmethod
    def _integer(
        value,
    ):
        try:
            return int(
                value
            )

        except (
            TypeError,
            ValueError,
        ):
            return 0

    @staticmethod
    def _number(
        value,
    ):
        try:
            return float(
                value
            )

        except (
            TypeError,
            ValueError,
        ):
            return 0
