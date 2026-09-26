from copy import deepcopy

from engine.presentation.report_read_model import (
    ReportReadModel,
)


class IncidentRepositoryStub:

    def __init__(
        self,
        rows=None,
        summary=None,
    ):
        self.rows = rows or []
        self.summary = (
            summary
            if summary is not None
            else {
                "incidents": len(
                    self.rows
                ),
                "high_critical": 0,
            }
        )

        self.recent_calls = []
        self.summary_calls = 0

    def list_recent(
        self,
        limit,
    ):
        self.recent_calls.append(
            limit
        )

        return deepcopy(
            self.rows[
                :limit
            ]
        )

    def summary_stats(
        self,
    ):
        self.summary_calls += 1

        return deepcopy(
            self.summary
        )

    def list_all(
        self,
    ):
        raise AssertionError(
            "list_all must not be used"
        )


class CampaignRepositoryStub:

    def __init__(
        self,
        rows=None,
        summary=None,
    ):
        self.rows = rows or []
        self.summary = (
            summary
            if summary is not None
            else {
                "campaigns": len(
                    self.rows
                ),
                "max_risk": 0,
            }
        )

        self.recent_calls = []
        self.summary_calls = 0

    def list_recent(
        self,
        limit,
    ):
        self.recent_calls.append(
            limit
        )

        return deepcopy(
            self.rows[
                :limit
            ]
        )

    def summary_stats(
        self,
    ):
        self.summary_calls += 1

        return deepcopy(
            self.summary
        )

    def list_all(
        self,
    ):
        raise AssertionError(
            "list_all must not be used"
        )


class CaseManagerStub:

    def __init__(
        self,
        rows=None,
    ):
        self.rows = rows or []
        self.recent_calls = []

    def list_recent(
        self,
        limit,
    ):
        self.recent_calls.append(
            limit
        )

        return deepcopy(
            self.rows[
                :limit
            ]
        )

    def list_cases(
        self,
    ):
        raise AssertionError(
            "list_cases must not be used"
        )


def build_model(
    incidents=None,
    campaigns=None,
    cases=None,
):
    incident_repository = (
        IncidentRepositoryStub(
            rows=incidents,
            summary={
                "incidents": 7,
                "high_critical": 3,
            },
        )
    )

    campaign_repository = (
        CampaignRepositoryStub(
            rows=campaigns,
            summary={
                "campaigns": 2,
                "max_risk": 91.5,
            },
        )
    )

    case_manager = CaseManagerStub(
        rows=cases,
    )

    model = ReportReadModel(
        incident_repository=(
            incident_repository
        ),
        campaign_repository=(
            campaign_repository
        ),
        case_manager=(
            case_manager
        ),
    )

    return (
        model,
        incident_repository,
        campaign_repository,
        case_manager,
    )


def test_snapshot_uses_bounded_sources():
    (
        model,
        incidents,
        campaigns,
        cases,
    ) = build_model()

    model.snapshot(
        incident_limit=12,
        campaign_limit=7,
        case_limit=5,
    )

    assert incidents.recent_calls == [
        12
    ]

    assert campaigns.recent_calls == [
        7
    ]

    assert cases.recent_calls == [
        5
    ]


def test_default_limits_are_explicit():
    (
        model,
        incidents,
        campaigns,
        cases,
    ) = build_model()

    model.snapshot()

    assert incidents.recent_calls == [
        50
    ]

    assert campaigns.recent_calls == [
        20
    ]

    assert cases.recent_calls == [
        20
    ]


def test_limits_are_capped_at_one_hundred():
    (
        model,
        incidents,
        campaigns,
        cases,
    ) = build_model()

    model.snapshot(
        incident_limit=1000,
        campaign_limit=1000,
        case_limit=1000,
    )

    assert incidents.recent_calls == [
        100
    ]

    assert campaigns.recent_calls == [
        100
    ]

    assert cases.recent_calls == [
        100
    ]


def test_zero_or_negative_limits_fail_closed():
    (
        model,
        incidents,
        campaigns,
        cases,
    ) = build_model()

    snapshot = model.snapshot(
        incident_limit=0,
        campaign_limit=-1,
        case_limit=0,
    )

    assert snapshot["incidents"] == []
    assert snapshot["campaigns"] == []
    assert snapshot["cases"] == []

    assert incidents.recent_calls == [
        0
    ]

    assert campaigns.recent_calls == [
        0
    ]

    assert cases.recent_calls == [
        0
    ]


def test_snapshot_summary_uses_aggregate_queries():
    (
        model,
        incidents,
        campaigns,
        _cases,
    ) = build_model()

    snapshot = model.snapshot()

    assert snapshot["summary"] == {
        "incidents": 7,
        "high_critical": 3,
        "campaigns": 2,
        "max_risk": 91.5,
    }

    assert incidents.summary_calls == 1
    assert campaigns.summary_calls == 1


def test_incident_projection_is_allowlist_controlled():
    (
        model,
        _incidents,
        _campaigns,
        _cases,
    ) = build_model(
        incidents=[
            {
                "id": "INC-1",
                "ip": "192.0.2.10",
                "severity": "HIGH",
                "status": "OPEN",
                "risk_score": 88,
                "campaign_id": "CMP-1",
                "created": "2026-01-01",
                "updated": "2026-01-02",
                "last_seen": "2026-01-02",
                "attack_phase": {
                    "tactic": (
                        "Credential Access"
                    ),
                    "technique_id": "T1110",
                },
                "timeline": [],
                "response_actions": [],
                "internal_note": "PRIVATE",
                "secret": "DO-NOT-EXPORT",
            }
        ]
    )

    incident = (
        model.snapshot()
        ["incidents"][0]
    )

    assert incident["id"] == "INC-1"
    assert incident["ip"] == "192.0.2.10"

    assert "internal_note" not in incident
    assert "secret" not in incident
    assert "alerts" not in incident


def test_campaign_projection_is_allowlist_controlled():
    (
        model,
        _incidents,
        _campaigns,
        _cases,
    ) = build_model(
        campaigns=[
            {
                "id": "CMP-1",
                "stage": "Persistence",
                "risk": 91,
                "incidents": [
                    "INC-1",
                ],
                "tactics": [
                    "Persistence",
                ],
                "created": "2026-01-01",
                "updated": "2026-01-02",
                "entities": {
                    "ip": [
                        "192.0.2.10",
                    ]
                },
                "debug": "PRIVATE",
            }
        ]
    )

    campaign = (
        model.snapshot()
        ["campaigns"][0]
    )

    assert campaign == {
        "id": "CMP-1",
        "stage": "Persistence",
        "risk": 91,
        "incidents": [
            "INC-1",
        ],
        "tactics": [
            "Persistence",
        ],
        "created": "2026-01-01",
        "updated": "2026-01-02",
    }


def test_case_projection_excludes_notes_and_evidence():
    (
        model,
        _incidents,
        _campaigns,
        _cases,
    ) = build_model(
        cases=[
            {
                "id": "CASE-1",
                "incident_id": "INC-1",
                "created": "2026-01-01",
                "status": "OPEN",
                "assignee": "analyst",
                "severity": "HIGH",
                "timeline": [],
                "notes": [
                    {
                        "note": "PRIVATE",
                    }
                ],
                "evidence": [
                    {
                        "evidence": (
                            "DO-NOT-EXPORT"
                        ),
                    }
                ],
            }
        ]
    )

    case = (
        model.snapshot()
        ["cases"][0]
    )

    assert case == {
        "id": "CASE-1",
        "incident_id": "INC-1",
        "created": "2026-01-01",
        "status": "OPEN",
        "assignee": "analyst",
        "severity": "HIGH",
        "timeline": [],
    }


def test_nested_forbidden_fields_are_rejected():
    (
        model,
        _incidents,
        _campaigns,
        _cases,
    ) = build_model(
        incidents=[
            {
                "id": "INC-1",
                "timeline": [
                    {
                        "event": "demo",
                        "raw_payload": (
                            "PRIVATE"
                        ),
                    }
                ],
            }
        ]
    )

    try:
        model.snapshot()
    except ValueError as exc:
        assert str(
            exc
        ) == (
            "Report payload contains "
            "forbidden export fields"
        )
    else:
        raise AssertionError(
            "Unsafe nested payload accepted"
        )


def test_snapshot_is_detached_from_sources():
    source = {
        "id": "INC-1",
        "timeline": [
            {
                "event": "demo",
            }
        ],
    }

    (
        model,
        _incidents,
        _campaigns,
        _cases,
    ) = build_model(
        incidents=[
            source
        ]
    )

    snapshot = model.snapshot()

    snapshot[
        "incidents"
    ][0][
        "timeline"
    ][0][
        "event"
    ] = "changed"

    assert (
        source[
            "timeline"
        ][0][
            "event"
        ]
        == "demo"
    )


def test_invalid_summary_values_fail_closed():
    incidents = IncidentRepositoryStub(
        summary={
            "incidents": "invalid",
            "high_critical": None,
        }
    )

    campaigns = CampaignRepositoryStub(
        summary={
            "campaigns": None,
            "max_risk": "invalid",
        }
    )

    cases = CaseManagerStub()

    model = ReportReadModel(
        incident_repository=incidents,
        campaign_repository=campaigns,
        case_manager=cases,
    )

    assert model.snapshot()["summary"] == {
        "incidents": 0,
        "high_critical": 0,
        "campaigns": 0,
        "max_risk": 0.0,
    }


def test_default_snapshot_excludes_advanced_sources():
    (
        model,
        _incidents,
        _campaigns,
        _cases,
    ) = build_model(
        incidents=[
            {
                "id": "INC-1",
                "threat_intel": {
                    "reputation": "suspicious",
                },
            }
        ],
        campaigns=[
            {
                "id": "CMP-1",
                "entities": {
                    "ip": [
                        "192.0.2.10",
                    ]
                },
            }
        ],
    )

    result = model.snapshot()

    assert (
        "threat_intel"
        not in result[
            "incidents"
        ][0]
    )

    assert (
        "entities"
        not in result[
            "campaigns"
        ][0]
    )


def test_advanced_snapshot_sanitizes_threat_intel():
    (
        model,
        _incidents,
        _campaigns,
        _cases,
    ) = build_model(
        incidents=[
            {
                "id": "INC-1",
                "threat_intel": {
                    "reputation": "suspicious",
                    "confidence": 88,
                    "country": "AR",
                    "known_attack": True,
                    "provider_debug": "PRIVATE",
                    "token": "SECRET",
                },
            }
        ]
    )

    result = model.snapshot(
        advanced=True
    )

    assert result[
        "incidents"
    ][0][
        "threat_intel"
    ] == {
        "reputation": "suspicious",
        "confidence": 88,
        "country": "AR",
        "known_attack": True,
    }

    serialized = repr(
        result
    )

    assert "provider_debug" not in serialized
    assert "PRIVATE" not in serialized
    assert "token" not in serialized
    assert "SECRET" not in serialized


def test_advanced_snapshot_sanitizes_campaign_entities():
    (
        model,
        _incidents,
        _campaigns,
        _cases,
    ) = build_model(
        campaigns=[
            {
                "id": "CMP-1",
                "entities": {
                    "ip": [
                        "192.0.2.10",
                    ],
                    "user": [
                        "augus",
                    ],
                    "host": [
                        "soc-win-01",
                    ],
                    "unknown": [
                        "DO-NOT-EXPORT",
                    ],
                },
            }
        ]
    )

    result = model.snapshot(
        advanced=True
    )

    assert result[
        "campaigns"
    ][0][
        "entities"
    ] == {
        "host": [
            "soc-win-01",
        ],
        "ip": [
            "192.0.2.10",
        ],
        "user": [
            "augus",
        ],
    }

    assert (
        "DO-NOT-EXPORT"
        not in repr(
            result
        )
    )


def test_advanced_snapshot_projects_persisted_hunt_findings():
    incidents = IncidentRepositoryStub(
        [
            {
                "id": "INC-HUNT-1",
                "hunt_findings": [
                    {
                        "type": (
                            "MITRE_CONTEXT_HUNT"
                        ),
                        "timestamp": (
                            "2026-09-26T20:00:00+00:00"
                        ),
                        "description": (
                            "Related activity detected"
                        ),
                        "action": "ssh_login",
                    }
                ],
            }
        ]
    )

    model = ReportReadModel(
        incident_repository=incidents,
        campaign_repository=(
            CampaignRepositoryStub([])
        ),
        case_manager=(
            CaseManagerStub([])
        ),
    )

    result = model.snapshot(
        advanced=True
    )

    assert result[
        "incidents"
    ][0][
        "hunt_findings"
    ] == [
        {
            "type": (
                "MITRE_CONTEXT_HUNT"
            ),
            "timestamp": (
                "2026-09-26T20:00:00+00:00"
            ),
            "description": (
                "Related activity detected"
            ),
            "action": "ssh_login",
        }
    ]


def test_advanced_snapshot_sanitizes_persisted_hunt_findings():
    incidents = IncidentRepositoryStub(
        [
            {
                "id": "INC-HUNT-2",
                "hunt_findings": [
                    {
                        "type": (
                            "MITRE_CONTEXT_HUNT"
                        ),
                        "timestamp": "safe-time",
                        "description": "safe",
                        "action": "safe-action",
                        "raw_event": {
                            "password": (
                                "DO-NOT-EXPORT"
                            )
                        },
                        "internal_note": (
                            "PRIVATE"
                        ),
                        "provider_debug": {
                            "secret": "hidden"
                        },
                    },
                    "invalid",
                    None,
                ],
            }
        ]
    )

    model = ReportReadModel(
        incident_repository=incidents,
        campaign_repository=(
            CampaignRepositoryStub([])
        ),
        case_manager=(
            CaseManagerStub([])
        ),
    )

    result = model.snapshot(
        advanced=True
    )

    findings = result[
        "incidents"
    ][0][
        "hunt_findings"
    ]

    assert findings == [
        {
            "type": (
                "MITRE_CONTEXT_HUNT"
            ),
            "timestamp": "safe-time",
            "description": "safe",
            "action": "safe-action",
        }
    ]

    rendered = str(
        result
    )

    assert "DO-NOT-EXPORT" not in rendered
    assert "PRIVATE" not in rendered
    assert "provider_debug" not in rendered
    assert "raw_event" not in rendered
    assert "password" not in rendered
    assert "secret" not in rendered


def test_technical_snapshot_never_exposes_hunt_findings():
    incidents = IncidentRepositoryStub(
        [
            {
                "id": "INC-HUNT-3",
                "hunt_findings": [
                    {
                        "type": (
                            "MITRE_CONTEXT_HUNT"
                        ),
                        "timestamp": "safe-time",
                        "description": "safe",
                        "action": "safe-action",
                    }
                ],
            }
        ]
    )

    model = ReportReadModel(
        incident_repository=incidents,
        campaign_repository=(
            CampaignRepositoryStub([])
        ),
        case_manager=(
            CaseManagerStub([])
        ),
    )

    result = model.snapshot(
        advanced=False
    )

    assert (
        "hunt_findings"
        not in result[
            "incidents"
        ][0]
    )
