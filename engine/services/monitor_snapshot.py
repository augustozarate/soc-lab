from datetime import datetime, timezone
import json
import os
import tempfile


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

class MonitorSnapshotWriter:

    def __init__(
        self,
        path
    ):
        self.path = path

    def write(
        self,
        snapshot
    ):

        directory = os.path.dirname(
            self.path
        )

        os.makedirs(
            directory,
            exist_ok=True
        )

        fd, temp_path = (
            tempfile.mkstemp(
                prefix=".monitor_snapshot_",
                suffix=".json.tmp",
                dir=directory
            )
        )

        try:

            with os.fdopen(
                fd,
                "w",
                encoding="utf-8"
            ) as f:

                json.dump(
                    snapshot,
                    f,
                    ensure_ascii=False,
                    indent=2
                )

                f.flush()

                os.fsync(
                    f.fileno()
                )

            os.replace(
                temp_path,
                self.path
            )

        except Exception:

            try:
                os.unlink(
                    temp_path
                )
            except FileNotFoundError:
                pass

            raise
