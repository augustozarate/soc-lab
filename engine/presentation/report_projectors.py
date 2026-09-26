from copy import deepcopy

from engine.presentation.reporting_contract import (
    REPORT_TYPE_ADVANCED,
    REPORT_TYPE_EXECUTIVE,
    REPORT_TYPE_TECHNICAL,
    assert_export_safe,
    normalize_report_type,
)


class ReportProjector:

    def project(
        self,
        snapshot,
        report_type,
        generated_at,
        period,
    ):
        normalized = normalize_report_type(
            report_type
        )

        snapshot = (
            deepcopy(snapshot)
            if isinstance(
                snapshot,
                dict,
            )
            else {}
        )

        metadata = {
            "report_type": normalized,
            "generated_at": str(
                generated_at
            ),
            "period": deepcopy(
                period
            ),
        }

        if normalized == REPORT_TYPE_EXECUTIVE:
            document = self._executive(
                snapshot,
                metadata,
            )

        elif normalized == REPORT_TYPE_TECHNICAL:
            document = self._technical(
                snapshot,
                metadata,
            )

        elif normalized == REPORT_TYPE_ADVANCED:
            document = self._advanced(
                snapshot,
                metadata,
            )

        else:
            raise ValueError(
                "Unsupported report type"
            )

        assert_export_safe(
            document
        )

        return deepcopy(
            document
        )

    def _executive(
        self,
        snapshot,
        metadata,
    ):
        summary = self._dict(
            snapshot.get(
                "summary"
            )
        )

        incidents = self._list(
            snapshot.get(
                "incidents"
            )
        )

        campaigns = self._list(
            snapshot.get(
                "campaigns"
            )
        )

        cases = self._list(
            snapshot.get(
                "cases"
            )
        )

        critical = [
            {
                "id": incident.get(
                    "id"
                ),
                "severity": incident.get(
                    "severity"
                ),
                "status": incident.get(
                    "status"
                ),
                "risk_score": incident.get(
                    "risk_score",
                    0,
                ),
            }
            for incident in incidents
            if str(
                incident.get(
                    "severity",
                    ""
                )
            ).upper() == "CRITICAL"
        ]

        max_incident_risk = max(
            (
                self._number(
                    incident.get(
                        "risk_score",
                        0,
                    )
                )
                for incident in incidents
            ),
            default=0.0,
        )

        max_campaign_risk = self._number(
            summary.get(
                "max_risk",
                0,
            )
        )

        risk = {
            "maximum": max(
                max_incident_risk,
                max_campaign_risk,
            ),
            "high_critical": self._integer(
                summary.get(
                    "high_critical",
                    0,
                )
            ),
        }

        response_overview = {
            "cases": len(
                cases
            ),
            "open_cases": sum(
                1
                for case in cases
                if str(
                    case.get(
                        "status",
                        ""
                    )
                ).upper()
                not in {
                    "CLOSED",
                    "RESOLVED",
                }
            ),
        }

        return {
            **metadata,
            "summary": {
                "incidents": self._integer(
                    summary.get(
                        "incidents",
                        0,
                    )
                ),
                "high_critical": self._integer(
                    summary.get(
                        "high_critical",
                        0,
                    )
                ),
                "campaigns": self._integer(
                    summary.get(
                        "campaigns",
                        0,
                    )
                ),
            },
            "risk": risk,
            "critical_incidents": critical,
            "campaigns": [
                {
                    "id": campaign.get(
                        "id"
                    ),
                    "stage": campaign.get(
                        "stage"
                    ),
                    "risk": campaign.get(
                        "risk",
                        0,
                    ),
                    "incidents": len(
                        campaign.get(
                            "incidents",
                            [],
                        )
                        or []
                    ),
                }
                for campaign in campaigns
            ],
            "response_overview": (
                response_overview
            ),
            "recommendations": (
                self._recommendations(
                    risk=risk,
                    critical_count=len(
                        critical
                    ),
                )
            ),
        }

    def _technical(
        self,
        snapshot,
        metadata,
    ):
        incidents = self._list(
            snapshot.get(
                "incidents"
            )
        )

        campaigns = self._list(
            snapshot.get(
                "campaigns"
            )
        )

        summary = self._dict(
            snapshot.get(
                "summary"
            )
        )

        mitre = []
        timeline = []
        response_actions = []

        seen_mitre = set()

        for incident in incidents:
            attack_phase = self._dict(
                incident.get(
                    "attack_phase"
                )
            )

            tactic = attack_phase.get(
                "tactic"
            )

            technique_id = (
                attack_phase.get(
                    "technique_id"
                )
            )

            technique = attack_phase.get(
                "technique"
            )

            key = (
                tactic,
                technique_id,
                technique,
            )

            if any(key) and key not in seen_mitre:
                seen_mitre.add(
                    key
                )

                mitre.append(
                    {
                        "tactic": tactic,
                        "technique_id": (
                            technique_id
                        ),
                        "technique": technique,
                    }
                )

            for entry in self._list(
                incident.get(
                    "timeline"
                )
            ):
                timeline.append(
                    {
                        "incident_id": (
                            incident.get(
                                "id"
                            )
                        ),
                        "time": entry.get(
                            "time"
                        ),
                        "event": entry.get(
                            "event"
                        ),
                    }
                )

            for action in self._list(
                incident.get(
                    "response_actions"
                )
            ):
                response_actions.append(
                    {
                        "incident_id": (
                            incident.get(
                                "id"
                            )
                        ),
                        "type": action.get(
                            "type"
                        ),
                        "status": action.get(
                            "status"
                        ),
                        "reason": action.get(
                            "reason"
                        ),
                        "backend_status": (
                            action.get(
                                "backend_status"
                            )
                        ),
                    }
                )

        return {
            **metadata,
            "summary": deepcopy(
                summary
            ),
            "incidents": deepcopy(
                incidents
            ),
            "campaigns": deepcopy(
                campaigns
            ),
            "mitre": mitre,
            "timeline": timeline,
            "response_actions": (
                response_actions
            ),
            "operational_status": {
                "source": (
                    "report-read-model"
                ),
                "state": "READ_ONLY",
            },
        }

    def _advanced(
        self,
        snapshot,
        metadata,
    ):
        technical = self._technical(
            snapshot,
            {
                **metadata,
                "report_type": (
                    REPORT_TYPE_ADVANCED
                ),
            },
        )

        cases = self._list(
            snapshot.get(
                "cases"
            )
        )

        return {
            **technical,
            "entities": [],
            "threat_intelligence": [],
            "hunting": [],
            "evidence": [
                {
                    "case_id": case.get(
                        "id"
                    ),
                    "incident_id": case.get(
                        "incident_id"
                    ),
                    "status": case.get(
                        "status"
                    ),
                    "assignee": case.get(
                        "assignee"
                    ),
                    "severity": case.get(
                        "severity"
                    ),
                    "timeline": deepcopy(
                        case.get(
                            "timeline",
                            [],
                        )
                        or []
                    ),
                }
                for case in cases
            ],
        }

    @staticmethod
    def _recommendations(
        risk,
        critical_count,
    ):
        recommendations = []

        maximum = float(
            risk.get(
                "maximum",
                0,
            )
            or 0
        )

        high_critical = int(
            risk.get(
                "high_critical",
                0,
            )
            or 0
        )

        if critical_count:
            recommendations.append(
                "Prioritize active critical "
                "incident investigation."
            )

        if maximum >= 80:
            recommendations.append(
                "Review containment posture "
                "for highest-risk activity."
            )

        if high_critical:
            recommendations.append(
                "Validate response coverage "
                "for high and critical events."
            )

        if not recommendations:
            recommendations.append(
                "Maintain current monitoring "
                "and review cadence."
            )

        return recommendations

    @staticmethod
    def _list(
        value,
    ):
        if not isinstance(
            value,
            list,
        ):
            return []

        return [
            deepcopy(
                item
            )
            for item in value
            if isinstance(
                item,
                dict,
            )
        ]

    @staticmethod
    def _dict(
        value,
    ):
        return (
            deepcopy(value)
            if isinstance(
                value,
                dict,
            )
            else {}
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
