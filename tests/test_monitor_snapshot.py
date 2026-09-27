from engine.services.monitor_snapshot import (
    MonitorSnapshotBuilder,
)


class IncidentRepository:

    def __init__(
        self,
    ):
        self.recent_calls = []
        self.summary_calls = 0
        self.list_all_calls = 0

    def list_recent(
        self,
        limit,
    ):
        self.recent_calls.append(
            limit
        )

        return [
            {
                "id": "INC-001",
                "ip": "192.0.2.10",
                "severity": "CRITICAL",
                "status": "OPEN",
                "risk_score": 95,
                "campaign_id": "CAMP-001",
                "last_seen": "now",
                "attack_phase": {
                    "tactic": (
                        "Credential Access"
                    ),
                    "technique_id": "T1110",
                    "technique": "Brute Force",
                },
                "alerts": [
                    {
                        "type": (
                            "UEBA_BRUTE_FORCE"
                        ),
                    },
                ],
                "threat_intel": {
                    "reputation": "malicious",
                    "confidence": 90,
                },
                "response_actions": [],
            },
        ][
            :limit
        ]

    def summary_stats(
        self,
    ):
        self.summary_calls += 1

        return {
            "incidents": 300,
            "high_critical": 80,
            "ueba_incidents": 27,
            "max_incident_risk": 99.5,
        }

    def list_all(
        self,
    ):
        self.list_all_calls += 1

        raise AssertionError(
            "Unbounded incident query reached"
        )


class CampaignRepository:

    def __init__(
        self,
    ):
        self.recent_calls = []
        self.summary_calls = 0
        self.list_all_calls = 0

    def list_recent(
        self,
        limit,
    ):
        self.recent_calls.append(
            limit
        )

        return [
            {
                "id": "CAMP-001",
                "risk": 91,
                "stage": "ACTIVE",
                "tactics": [
                    "Credential Access",
                ],
                "incidents": [
                    "INC-001",
                ],
                "updated": "now",
            },
        ][
            :limit
        ]

    def summary_stats(
        self,
    ):
        self.summary_calls += 1

        return {
            "campaigns": 41,
            "max_risk": 91,
        }

    def list_all(
        self,
    ):
        self.list_all_calls += 1

        raise AssertionError(
            "Unbounded campaign query reached"
        )


def build_builder():
    incidents = IncidentRepository()
    campaigns = CampaignRepository()

    return (
        MonitorSnapshotBuilder(
            incident_repository=incidents,
            campaign_repository=campaigns,
        ),
        incidents,
        campaigns,
    )


def test_snapshot_uses_bounded_recent_queries():
    builder, incidents, campaigns = (
        build_builder()
    )

    snapshot = builder.build()

    assert incidents.recent_calls == [
        100
    ]

    assert campaigns.recent_calls == [
        100
    ]

    assert incidents.list_all_calls == 0
    assert campaigns.list_all_calls == 0

    assert len(
        snapshot["incidents"]
    ) == 1

    assert len(
        snapshot["campaigns"]
    ) == 1


def test_snapshot_limits_are_hard_capped():
    builder, incidents, campaigns = (
        build_builder()
    )

    builder.build(
        incident_limit=9999,
        campaign_limit=9999,
    )

    assert incidents.recent_calls == [
        100
    ]

    assert campaigns.recent_calls == [
        100
    ]


def test_snapshot_zero_limits_return_no_rows():
    builder, incidents, campaigns = (
        build_builder()
    )

    snapshot = builder.build(
        incident_limit=0,
        campaign_limit=0,
    )

    assert incidents.recent_calls == [
        0
    ]

    assert campaigns.recent_calls == [
        0
    ]

    assert snapshot["incidents"] == []
    assert snapshot["campaigns"] == []


def test_snapshot_summary_uses_global_aggregates():
    builder, incidents, campaigns = (
        build_builder()
    )

    snapshot = builder.build(
        incident_limit=1,
        campaign_limit=1,
    )

    assert snapshot["summary"] == {
        "total_incidents": 300,
        "high_or_critical": 80,
        "ueba_incidents": 27,
        "total_campaigns": 41,
        "max_incident_risk": 99.5,
    }

    assert incidents.summary_calls == 1
    assert campaigns.summary_calls == 1


def test_snapshot_keeps_rich_bounded_views():
    builder, _, _ = build_builder()

    snapshot = builder.build()

    incident = snapshot[
        "incidents"
    ][0]

    assert incident[
        "id"
    ] == "INC-001"

    assert incident[
        "technique_id"
    ] == "T1110"

    assert incident[
        "threat_reputation"
    ] == "malicious"

    campaign = snapshot[
        "campaigns"
    ][0]

    assert campaign[
        "id"
    ] == "CAMP-001"

    assert campaign[
        "incident_count"
    ] == 1
