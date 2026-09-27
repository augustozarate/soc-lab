from datetime import datetime, timezone

from engine.services.atomic_json_writer import (
    AtomicJsonWriter
)


class MonitorSnapshotBuilder:

    DEFAULT_INCIDENT_LIMIT = 100
    DEFAULT_CAMPAIGN_LIMIT = 100

    MAX_INCIDENT_LIMIT = 100
    MAX_CAMPAIGN_LIMIT = 100

    def __init__(
        self,
        incident_repository,
        campaign_repository
    ):

        self.incident_repository = (
            incident_repository
        )

        self.campaign_repository = (
            campaign_repository
        )

    # =========================================

    def build(
        self,
        incident_limit=DEFAULT_INCIDENT_LIMIT,
        campaign_limit=DEFAULT_CAMPAIGN_LIMIT,
    ):

        bounded_incident_limit = (
            self._bounded_limit(
                incident_limit,
                default=self.DEFAULT_INCIDENT_LIMIT,
                maximum=self.MAX_INCIDENT_LIMIT,
            )
        )

        bounded_campaign_limit = (
            self._bounded_limit(
                campaign_limit,
                default=self.DEFAULT_CAMPAIGN_LIMIT,
                maximum=self.MAX_CAMPAIGN_LIMIT,
            )
        )

        incidents = (
            self.incident_repository
            .list_recent(
                limit=bounded_incident_limit
            )
        )

        campaigns = (
            self.campaign_repository
            .list_recent(
                limit=bounded_campaign_limit
            )
        )

        incident_summary = (
            self.incident_repository
            .summary_stats()
        )

        campaign_summary = (
            self.campaign_repository
            .summary_stats()
        )

        incident_views = [
            self._incident_view(
                incident
            )
            for incident in (
                incidents
                if isinstance(
                    incidents,
                    list,
                )
                else []
            )
        ]

        campaign_views = [
            self._campaign_view(
                campaign
            )
            for campaign in (
                campaigns
                if isinstance(
                    campaigns,
                    list,
                )
                else []
            )
        ]

        return {
            "generated_at": (
                datetime.now(
                    timezone.utc
                ).isoformat()
            ),

            "summary": (
                self._build_summary(
                    incident_summary,
                    campaign_summary,
                )
            ),

            "incidents": (
                incident_views
            ),

            "campaigns": (
                campaign_views
            )
        }

    # =========================================

    def _incident_view(
        self,
        incident
    ):

        attack_phase = (
            incident.get(
                "attack_phase"
            )
            or {}
        )

        threat_intel = (
            incident.get(
                "threat_intel"
            )
            or {}
        )

        alerts = (
            incident.get(
                "alerts"
            )
            or []
        )

        response_actions = (
            incident.get(
                "response_actions"
            )
            or []
        )

        return {
            "id": incident.get("id"),
            "ip": incident.get("ip"),
            "severity": (
                incident.get("severity")
            ),
            "status": (
                incident.get("status")
            ),
            "risk_score": (
                incident.get(
                    "risk_score",
                    0
                )
            ),
            "campaign_id": (
                incident.get(
                    "campaign_id"
                )
            ),
            "last_seen": (
                incident.get(
                    "last_seen"
                )
            ),

            "tactic": (
                attack_phase.get(
                    "tactic"
                )
            ),

            "technique_id": (
                attack_phase.get(
                    "technique_id"
                )
            ),

            "technique": (
                attack_phase.get(
                    "technique"
                )
            ),

            "alert_types": [
                alert.get("type")
                or alert.get("rule_id")
                for alert in alerts
            ],

            "threat_reputation": (
                threat_intel.get(
                    "reputation",
                    "unknown"
                )
            ),

            "threat_confidence": (
                threat_intel.get(
                    "confidence"
                )
            ),

            "response_actions": [
                {
                    "type": action.get(
                        "type"
                    ),
                    "status": action.get(
                        "status"
                    )
                }
                for action
                in response_actions
            ]
        }

    # =========================================

    def _campaign_view(
        self,
        campaign
    ):

        return {
            "id": campaign.get("id"),
            "risk": campaign.get(
                "risk",
                0
            ),
            "stage": campaign.get(
                "stage"
            ),
            "tactics": campaign.get(
                "tactics",
                []
            ),
            "incident_count": len(
                campaign.get(
                    "incidents",
                    []
                )
            ),
            "updated": campaign.get(
                "updated"
            )
        }

    # =========================================

    def _build_summary(
        self,
        incident_summary,
        campaign_summary,
    ):

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
            "total_incidents": self._integer(
                incident_summary.get(
                    "incidents",
                    0,
                )
            ),
            "high_or_critical": self._integer(
                incident_summary.get(
                    "high_critical",
                    0,
                )
            ),
            "ueba_incidents": self._integer(
                incident_summary.get(
                    "ueba_incidents",
                    0,
                )
            ),
            "total_campaigns": self._integer(
                campaign_summary.get(
                    "campaigns",
                    0,
                )
            ),
            "max_incident_risk": self._number(
                incident_summary.get(
                    "max_incident_risk",
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
            return 0.0



class MonitorSnapshotWriter(
    AtomicJsonWriter
):

    def __init__(
        self,
        path
    ):

        super().__init__(
            path=path,
            temp_prefix=".monitor_snapshot_"
        )
