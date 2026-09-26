from copy import deepcopy
from datetime import datetime
from datetime import timezone

from engine.presentation.report_projectors import (
    ReportProjector,
)


class ReportDocumentBuilder:

    def __init__(
        self,
        read_model,
        projector=None,
        clock=None,
    ):
        self.read_model = read_model

        self.projector = (
            projector
            or ReportProjector()
        )

        self.clock = (
            clock
            or self._utc_now
        )

    def build(
        self,
        report_type,
        period=None,
        incident_limit=None,
        campaign_limit=None,
        case_limit=None,
    ):
        kwargs = {}

        if incident_limit is not None:
            kwargs[
                "incident_limit"
            ] = incident_limit

        if campaign_limit is not None:
            kwargs[
                "campaign_limit"
            ] = campaign_limit

        if case_limit is not None:
            kwargs[
                "case_limit"
            ] = case_limit

        snapshot = (
            self.read_model
            .snapshot(
                **kwargs
            )
        )

        generated_at = (
            self.clock()
        )

        normalized_period = (
            deepcopy(period)
            if isinstance(
                period,
                dict,
            )
            else {
                "label": (
                    "current-snapshot"
                )
            }
        )

        return (
            self.projector
            .project(
                snapshot=snapshot,
                report_type=report_type,
                generated_at=generated_at,
                period=(
                    normalized_period
                ),
            )
        )

    @staticmethod
    def _utc_now():
        return (
            datetime.now(
                timezone.utc
            )
            .isoformat()
        )
