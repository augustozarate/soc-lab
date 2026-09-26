from copy import deepcopy

from engine.presentation.report_projectors import (
    ReportProjector,
)


def snapshot():
    return {
        "summary": {
            "incidents": 3,
            "high_critical": 2,
            "campaigns": 1,
            "max_risk": 92,
        },
        "incidents": [
            {
                "id": "INC-1",
                "ip": "192.0.2.10",
                "severity": "CRITICAL",
                "status": "OPEN",
                "risk_score": 95,
                "campaign_id": "CMP-1",
                "created": "2026-01-01",
                "updated": "2026-01-02",
                "last_seen": "2026-01-02",
                "attack_phase": {
                    "tactic": (
                        "Credential Access"
                    ),
                    "technique_id": "T1110",
                    "technique": (
                        "Brute Force"
                    ),
                },
                "timeline": [
                    {
                        "time": "10:00",
                        "event": (
                            "Authentication anomaly"
                        ),
                    }
                ],
                "response_actions": [
                    {
                        "type": "BLOCK_IP",
                        "status": "SUCCESS",
                        "reason": "High risk",
                        "backend_status": (
                            "BLOCKED"
                        ),
                    }
                ],
            },
            {
                "id": "INC-2",
                "severity": "HIGH",
                "status": "INVESTIGATING",
                "risk_score": 82,
                "timeline": [],
                "response_actions": [],
            },
            {
                "id": "INC-3",
                "severity": "LOW",
                "status": "OPEN",
                "risk_score": 10,
                "timeline": [],
                "response_actions": [],
            },
        ],
        "campaigns": [
            {
                "id": "CMP-1",
                "stage": "Persistence",
                "risk": 92,
                "incidents": [
                    "INC-1",
                    "INC-2",
                ],
                "tactics": [
                    "Credential Access",
                    "Persistence",
                ],
                "created": "2026-01-01",
                "updated": "2026-01-02",
            }
        ],
        "cases": [
            {
                "id": "CASE-1",
                "incident_id": "INC-1",
                "created": "2026-01-01",
                "status": "OPEN",
                "assignee": "analyst",
                "severity": "CRITICAL",
                "timeline": [
                    {
                        "time": "10:05",
                        "event": (
                            "Assigned to analyst"
                        ),
                    }
                ],
            }
        ],
    }


def project(
    report_type,
):
    return ReportProjector().project(
        snapshot=snapshot(),
        report_type=report_type,
        generated_at=(
            "2026-09-26T12:00:00+00:00"
        ),
        period={
            "label": "demo",
        },
    )


def test_executive_report_has_expected_surface():
    report = project(
        "executive"
    )

    assert set(
        report
    ) == {
        "report_type",
        "generated_at",
        "period",
        "summary",
        "risk",
        "critical_incidents",
        "campaigns",
        "response_overview",
        "recommendations",
    }


def test_executive_report_excludes_ip_and_timeline():
    report = project(
        "executive"
    )

    serialized = repr(
        report
    )

    assert "192.0.2.10" not in serialized
    assert "Authentication anomaly" not in serialized


def test_executive_report_identifies_critical_incident():
    report = project(
        "executive"
    )

    assert report[
        "critical_incidents"
    ] == [
        {
            "id": "INC-1",
            "severity": "CRITICAL",
            "status": "OPEN",
            "risk_score": 95,
        }
    ]


def test_executive_report_summarizes_risk():
    report = project(
        "executive"
    )

    assert report["risk"] == {
        "maximum": 95.0,
        "high_critical": 2,
    }


def test_executive_report_generates_deterministic_recommendations():
    report = project(
        "executive"
    )

    assert report[
        "recommendations"
    ] == [
        (
            "Prioritize active critical "
            "incident investigation."
        ),
        (
            "Review containment posture "
            "for highest-risk activity."
        ),
        (
            "Validate response coverage "
            "for high and critical events."
        ),
    ]


def test_technical_report_has_expected_surface():
    report = project(
        "technical"
    )

    assert set(
        report
    ) == {
        "report_type",
        "generated_at",
        "period",
        "summary",
        "incidents",
        "campaigns",
        "mitre",
        "timeline",
        "response_actions",
        "operational_status",
    }


def test_technical_report_aggregates_mitre():
    report = project(
        "technical"
    )

    assert report["mitre"] == [
        {
            "tactic": (
                "Credential Access"
            ),
            "technique_id": "T1110",
            "technique": "Brute Force",
        }
    ]


def test_technical_report_builds_flat_timeline():
    report = project(
        "technical"
    )

    assert report["timeline"] == [
        {
            "incident_id": "INC-1",
            "time": "10:00",
            "event": (
                "Authentication anomaly"
            ),
        }
    ]


def test_technical_report_builds_response_action_view():
    report = project(
        "technical"
    )

    assert report[
        "response_actions"
    ] == [
        {
            "incident_id": "INC-1",
            "type": "BLOCK_IP",
            "status": "SUCCESS",
            "reason": "High risk",
            "backend_status": "BLOCKED",
        }
    ]


def test_advanced_report_extends_technical_surface():
    report = project(
        "advanced"
    )

    assert report[
        "report_type"
    ] == "advanced"

    assert "entities" in report
    assert "threat_intelligence" in report
    assert "hunting" in report
    assert "evidence" in report


def test_advanced_evidence_uses_safe_case_projection():
    report = project(
        "advanced"
    )

    assert report["evidence"] == [
        {
            "case_id": "CASE-1",
            "incident_id": "INC-1",
            "status": "OPEN",
            "assignee": "analyst",
            "severity": "CRITICAL",
            "timeline": [
                {
                    "time": "10:05",
                    "event": (
                        "Assigned to analyst"
                    ),
                }
            ],
        }
    ]


def test_projection_is_detached_from_snapshot():
    source = snapshot()

    report = ReportProjector().project(
        snapshot=source,
        report_type="technical",
        generated_at="now",
        period={
            "label": "demo",
        },
    )

    report[
        "incidents"
    ][0][
        "status"
    ] = "CHANGED"

    assert (
        source[
            "incidents"
        ][0][
            "status"
        ]
        == "OPEN"
    )


def test_unsafe_nested_fields_are_rejected():
    source = snapshot()

    source[
        "incidents"
    ][0][
        "timeline"
    ][0][
        "raw_payload"
    ] = "PRIVATE"

    try:
        ReportProjector().project(
            snapshot=source,
            report_type="technical",
            generated_at="now",
            period={
                "label": "demo",
            },
        )
    except ValueError as exc:
        assert str(
            exc
        ) == (
            "Report payload contains "
            "forbidden export fields"
        )
    else:
        raise AssertionError(
            "Unsafe report accepted"
        )


def test_projector_does_not_mutate_input():
    source = snapshot()
    original = deepcopy(
        source
    )

    ReportProjector().project(
        snapshot=source,
        report_type="advanced",
        generated_at="now",
        period={
            "label": "demo",
        },
    )

    assert source == original


def test_executive_reduces_forbidden_source_fields_away():
    source = snapshot()

    source[
        "incidents"
    ][0][
        "secret"
    ] = "DO-NOT-EXPORT"

    source[
        "incidents"
    ][0][
        "internal_note"
    ] = "PRIVATE"

    source[
        "incidents"
    ][0][
        "debug"
    ] = "PRIVATE-DEBUG"

    report = ReportProjector().project(
        snapshot=source,
        report_type="executive",
        generated_at="now",
        period={
            "label": "probe",
        },
    )

    serialized = repr(
        report
    )

    for marker in (
        "DO-NOT-EXPORT",
        "PRIVATE",
        "PRIVATE-DEBUG",
        "secret",
        "internal_note",
        "debug",
    ):
        assert marker not in serialized


def test_technical_rejects_forbidden_incident_fields():
    source = snapshot()

    source[
        "incidents"
    ][0][
        "secret"
    ] = "DO-NOT-EXPORT"

    try:
        ReportProjector().project(
            snapshot=source,
            report_type="technical",
            generated_at="now",
            period={
                "label": "probe",
            },
        )

    except ValueError as exc:
        assert str(
            exc
        ) == (
            "Report payload contains "
            "forbidden export fields"
        )

    else:
        raise AssertionError(
            "Technical report accepted "
            "forbidden incident field"
        )


def test_advanced_reduces_forbidden_top_level_incident_fields():
    source = snapshot()

    source[
        "incidents"
    ][0][
        "internal_note"
    ] = "PRIVATE"

    source[
        "incidents"
    ][0][
        "secret"
    ] = "DO-NOT-EXPORT"

    report = ReportProjector().project(
        snapshot=source,
        report_type="advanced",
        generated_at="now",
        period={
            "label": "probe",
        },
    )

    serialized = repr(
        report
    )

    for marker in (
        "internal_note",
        "secret",
        "PRIVATE",
        "DO-NOT-EXPORT",
    ):
        assert marker not in serialized


def test_advanced_report_technical_surface_stays_sanitized():
    source = snapshot()

    source[
        "incidents"
    ][0][
        "threat_intel"
    ] = {
        "reputation": "suspicious",
        "confidence": 88,
    }

    source[
        "campaigns"
    ][0][
        "entities"
    ] = {
        "ip": [
            "192.0.2.10",
        ],
    }

    report = ReportProjector().project(
        snapshot=source,
        report_type="advanced",
        generated_at="now",
        period={
            "label": "demo",
        },
    )

    assert (
        "threat_intel"
        not in report[
            "incidents"
        ][0]
    )

    assert (
        "entities"
        not in report[
            "campaigns"
        ][0]
    )


def test_advanced_report_projects_campaign_entities():
    source = snapshot()

    source[
        "campaigns"
    ][0][
        "entities"
    ] = {
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

    report = ReportProjector().project(
        snapshot=source,
        report_type="advanced",
        generated_at="now",
        period={
            "label": "demo",
        },
    )

    assert report["entities"] == [
        {
            "campaign_id": "CMP-1",
            "type": "host",
            "value": "soc-win-01",
        },
        {
            "campaign_id": "CMP-1",
            "type": "ip",
            "value": "192.0.2.10",
        },
        {
            "campaign_id": "CMP-1",
            "type": "user",
            "value": "augus",
        },
    ]


def test_advanced_report_projects_real_threat_intelligence():
    source = snapshot()

    source[
        "incidents"
    ][0][
        "threat_intel"
    ] = {
        "reputation": "suspicious",
        "confidence": 88,
        "country": "AR",
        "known_attack": True,
    }

    report = ReportProjector().project(
        snapshot=source,
        report_type="advanced",
        generated_at="now",
        period={
            "label": "demo",
        },
    )

    assert report[
        "threat_intelligence"
    ] == [
        {
            "incident_id": "INC-1",
            "reputation": "suspicious",
            "confidence": 88,
            "country": "AR",
            "known_attack": True,
        }
    ]


def test_advanced_hunting_remains_empty_without_persisted_source():
    source = snapshot()

    report = ReportProjector().project(
        snapshot=source,
        report_type="advanced",
        generated_at="now",
        period={
            "label": "demo",
        },
    )

    assert report[
        "hunting"
    ] == []



def _persisted_hunting_snapshot():
    return {
        "summary": {
            "incidents": 1,
            "high_critical": 1,
            "campaigns": 0,
            "max_risk": 0,
        },
        "incidents": [
            {
                "id": "INC-1",
                "ip": "192.0.2.10",
                "severity": "HIGH",
                "status": "OPEN",
                "risk_score": 80,
                "timeline": [],
                "response_actions": [],
            }
        ],
        "campaigns": [],
        "cases": [],
    }


def test_advanced_report_projects_persisted_hunting():
    snapshot = _persisted_hunting_snapshot()

    snapshot["incidents"][0]["hunt_findings"] = [
        {
            "type": "MITRE_CONTEXT_HUNT",
            "timestamp": (
                "2026-09-26T20:00:00+00:00"
            ),
            "description": (
                "Related activity detected"
            ),
            "action": "ssh_login",
        }
    ]

    report = ReportProjector().project(
        snapshot=snapshot,
        report_type="advanced",
        generated_at=(
            "2026-09-26T20:30:00+00:00"
        ),
        period={
            "label": "audit",
        },
    )

    assert report["hunting"] == [
        {
            "incident_id": "INC-1",
            "type": "MITRE_CONTEXT_HUNT",
            "timestamp": (
                "2026-09-26T20:00:00+00:00"
            ),
            "description": (
                "Related activity detected"
            ),
            "action": "ssh_login",
        }
    ]


def test_advanced_hunting_deduplicates_persisted_findings():
    snapshot = _persisted_hunting_snapshot()

    finding = {
        "type": "MITRE_CONTEXT_HUNT",
        "timestamp": "safe-time",
        "description": "safe",
        "action": "safe-action",
    }

    snapshot["incidents"][0]["hunt_findings"] = [
        dict(finding),
        dict(finding),
    ]

    report = ReportProjector().project(
        snapshot=snapshot,
        report_type="advanced",
        generated_at="now",
        period={
            "label": "audit",
        },
    )

    assert len(
        report["hunting"]
    ) == 1


def test_advanced_hunting_does_not_execute_live_hunter():
    snapshot = _persisted_hunting_snapshot()

    report = ReportProjector().project(
        snapshot=snapshot,
        report_type="advanced",
        generated_at="now",
        period={
            "label": "audit",
        },
    )

    assert report["hunting"] == []
