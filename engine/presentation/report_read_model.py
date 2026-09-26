from copy import deepcopy

from engine.presentation.reporting_contract import (
    CAMPAIGN_FIELDS,
    CASE_FIELDS,
    TECHNICAL_INCIDENT_FIELDS,
    assert_export_safe,
    project_fields,
)


class ReportReadModel:

    DEFAULT_INCIDENT_LIMIT = 50
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

    def snapshot(
        self,
        incident_limit=DEFAULT_INCIDENT_LIMIT,
        campaign_limit=DEFAULT_CAMPAIGN_LIMIT,
        case_limit=DEFAULT_CASE_LIMIT,
    ):
        incidents = self._incidents(
            incident_limit
        )

        campaigns = self._campaigns(
            campaign_limit
        )

        cases = self._cases(
            case_limit
        )

        snapshot = {
            "summary": self._summary(),
            "incidents": incidents,
            "campaigns": campaigns,
            "cases": cases,
        }

        assert_export_safe(
            snapshot
        )

        return deepcopy(
            snapshot
        )

    def _summary(self):
        incident_summary = (
            self.incident_repository
            .summary_stats()
        )

        campaign_summary = (
            self.campaign_repository
            .summary_stats()
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

    def _incidents(
        self,
        limit,
    ):
        bounded_limit = self._bounded_limit(
            limit,
            default=self.DEFAULT_INCIDENT_LIMIT,
            maximum=self.MAX_INCIDENT_LIMIT,
        )

        rows = (
            self.incident_repository
            .list_recent(
                limit=bounded_limit,
            )
        )

        return [
            project_fields(
                row,
                TECHNICAL_INCIDENT_FIELDS,
            )
            for row in (
                rows
                if isinstance(
                    rows,
                    list,
                )
                else []
            )
        ]

    def _campaigns(
        self,
        limit,
    ):
        bounded_limit = self._bounded_limit(
            limit,
            default=self.DEFAULT_CAMPAIGN_LIMIT,
            maximum=self.MAX_CAMPAIGN_LIMIT,
        )

        rows = (
            self.campaign_repository
            .list_recent(
                limit=bounded_limit,
            )
        )

        return [
            project_fields(
                row,
                CAMPAIGN_FIELDS,
            )
            for row in (
                rows
                if isinstance(
                    rows,
                    list,
                )
                else []
            )
        ]

    def _cases(
        self,
        limit,
    ):
        bounded_limit = self._bounded_limit(
            limit,
            default=self.DEFAULT_CASE_LIMIT,
            maximum=self.MAX_CASE_LIMIT,
        )

        rows = (
            self.case_manager
            .list_recent(
                limit=bounded_limit,
            )
        )

        return [
            project_fields(
                row,
                CASE_FIELDS,
            )
            for row in (
                rows
                if isinstance(
                    rows,
                    list,
                )
                else []
            )
        ]

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
            return 0.0
