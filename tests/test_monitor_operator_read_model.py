from engine.presentation.monitor_operator_read_model import (
    MonitorOperatorReadModel,
)


class FakeIncidentRepository:

    def __init__(
        self,
        incidents=None,
        summary=None,
    ):
        self.incidents = list(
            incidents or []
        )

        self.summary = (
            {
                "incidents": len(
                    self.incidents
                ),
                "high_critical": 0,
            }
            if summary is None
            else dict(
                summary
            )
        )

        self.summary_calls = 0
        self.recent_calls = []
        self.list_all_calls = 0

    def summary_stats(self):
        self.summary_calls += 1

        return dict(
            self.summary
        )

    def list_recent(
        self,
        limit,
    ):
        self.recent_calls.append(
            limit
        )

        return [
            dict(
                incident
            )
            for incident in (
                self.incidents[:limit]
            )
        ]

    def list_all(self):
        self.list_all_calls += 1

        raise AssertionError(
            "list_all must not be used"
        )


class FakeCampaignRepository:

    def __init__(
        self,
        summary=None,
    ):
        self.summary = (
            {
                "campaigns": 0,
                "max_risk": 0.0,
            }
            if summary is None
            else dict(
                summary
            )
        )

        self.summary_calls = 0
        self.list_all_calls = 0

    def summary_stats(self):
        self.summary_calls += 1

        return dict(
            self.summary
        )

    def list_all(self):
        self.list_all_calls += 1

        raise AssertionError(
            "list_all must not be used"
        )


def build_model(
    incidents=None,
    incident_summary=None,
    campaign_summary=None,
):
    incident_repository = (
        FakeIncidentRepository(
            incidents=incidents,
            summary=incident_summary,
        )
    )

    campaign_repository = (
        FakeCampaignRepository(
            summary=campaign_summary,
        )
    )

    model = (
        MonitorOperatorReadModel(
            incident_repository=(
                incident_repository
            ),
            campaign_repository=(
                campaign_repository
            ),
        )
    )

    return (
        model,
        incident_repository,
        campaign_repository,
    )


def test_snapshot_has_reduced_contract():
    model, _, _ = build_model(
        incidents=[
            {
                "id": "INC-001",
                "severity": "HIGH",
            },
        ],
        incident_summary={
            "incidents": 7,
            "high_critical": 3,
        },
        campaign_summary={
            "campaigns": 2,
            "max_risk": 88.5,
        },
    )

    snapshot = model.snapshot()

    assert snapshot == {
        "summary": {
            "incidents": 7,
            "high_critical": 3,
            "campaigns": 2,
            "max_risk": 88.5,
        },
        "incidents": [
            {
                "id": "INC-001",
                "severity": "HIGH",
            },
        ],
    }


def test_snapshot_uses_exact_aggregate_queries_once():
    model, incidents, campaigns = (
        build_model()
    )

    model.snapshot()

    assert incidents.summary_calls == 1
    assert campaigns.summary_calls == 1


def test_snapshot_uses_only_bounded_recent_incidents():
    model, incidents, _ = build_model(
        incidents=[
            {
                "id": f"INC-{index:03d}",
                "severity": "LOW",
            }
            for index in range(
                50
            )
        ]
    )

    snapshot = model.snapshot(
        incident_limit=7
    )

    assert incidents.recent_calls == [
        7
    ]

    assert len(
        snapshot["incidents"]
    ) == 7

    assert incidents.list_all_calls == 0


def test_campaign_list_all_is_never_used():
    model, _, campaigns = (
        build_model()
    )

    model.snapshot()

    assert campaigns.list_all_calls == 0


def test_zero_limit_returns_no_incidents():
    model, incidents, _ = build_model(
        incidents=[
            {
                "id": "INC-001",
                "severity": "HIGH",
            },
        ]
    )

    snapshot = model.snapshot(
        incident_limit=0
    )

    assert incidents.recent_calls == [
        0
    ]

    assert (
        snapshot["incidents"]
        == []
    )


def test_negative_limit_is_zero():
    model, incidents, _ = build_model()

    model.snapshot(
        incident_limit=-10
    )

    assert incidents.recent_calls == [
        0
    ]


def test_invalid_limit_uses_default():
    model, incidents, _ = build_model()

    model.snapshot(
        incident_limit="invalid"
    )

    assert incidents.recent_calls == [
        10
    ]


def test_limit_is_hard_capped():
    model, incidents, _ = build_model()

    model.snapshot(
        incident_limit=9999
    )

    assert incidents.recent_calls == [
        100
    ]


def test_snapshot_is_detached_from_sources():
    source_incidents = [
        {
            "id": "INC-001",
            "severity": "CRITICAL",
        },
    ]

    model, incidents, _ = build_model(
        incidents=source_incidents
    )

    snapshot = model.snapshot()

    snapshot["incidents"][0][
        "severity"
    ] = "LOW"

    assert (
        incidents.incidents[0][
            "severity"
        ]
        == "CRITICAL"
    )


def test_snapshots_are_independent():
    model, _, _ = build_model(
        incidents=[
            {
                "id": "INC-001",
                "severity": "HIGH",
            },
        ]
    )

    first = model.snapshot()
    second = model.snapshot()

    first["incidents"][0][
        "severity"
    ] = "LOW"

    assert (
        second["incidents"][0][
            "severity"
        ]
        == "HIGH"
    )


def test_missing_summary_keys_fail_safe():
    model, _, _ = build_model(
        incident_summary={},
        campaign_summary={},
    )

    snapshot = model.snapshot()

    assert snapshot["summary"] == {
        "incidents": 0,
        "high_critical": 0,
        "campaigns": 0,
        "max_risk": 0,
    }


def test_read_model_exposes_no_write_methods():
    forbidden = {
        "save",
        "write",
        "update",
        "delete",
        "remove",
        "send",
        "dispatch",
        "block",
        "release",
        "acknowledge",
        "enable",
        "disable",
    }

    public_methods = {
        name
        for name in dir(
            MonitorOperatorReadModel
        )
        if not name.startswith(
            "_"
        )
        and callable(
            getattr(
                MonitorOperatorReadModel,
                name,
            )
        )
    }

    assert not (
        public_methods
        & forbidden
    )
