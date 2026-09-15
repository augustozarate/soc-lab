from datetime import datetime, timezone

from engine.services.atomic_json_writer import (
    AtomicJsonWriter
)


class MonitorSnapshotBuilder:

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

    def build(self):

        incidents = (
            self.incident_repository
            .list_all()
        )

        campaigns = (
            self.campaign_repository
            .list_all()
        )

        incident_views = [
            self._incident_view(
                incident
            )
            for incident in incidents
        ]

        campaign_views = [
            self._campaign_view(
                campaign
            )
            for campaign in campaigns
        ]

        return {
            "generated_at": (
                datetime.now(
                    timezone.utc
                ).isoformat()
            ),

            "summary": (
                self._build_summary(
                    incident_views,
                    campaign_views
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
        incidents,
        campaigns
    ):

        high_or_critical = sum(
            1
            for incident in incidents
            if incident.get(
                "severity"
            )
            in {
                "HIGH",
                "CRITICAL"
            }
        )

        ueba_incidents = sum(
            1
            for incident in incidents
            if "UEBA_BRUTE_FORCE"
            in incident.get(
                "alert_types",
                []
            )
        )

        max_risk = max(
            (
                incident.get(
                    "risk_score",
                    0
                )
                for incident
                in incidents
            ),
            default=0
        )

        return {
            "total_incidents": len(
                incidents
            ),
            "high_or_critical": (
                high_or_critical
            ),
            "ueba_incidents": (
                ueba_incidents
            ),
            "total_campaigns": len(
                campaigns
            ),
            "max_incident_risk": (
                max_risk
            )
        }


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
