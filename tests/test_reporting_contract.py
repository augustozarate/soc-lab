from engine.presentation.reporting_contract import (
    ADVANCED_CASE_FIELDS,
    ADVANCED_FIELDS,
    ADVANCED_INCIDENT_FIELDS,
    CAMPAIGN_FIELDS,
    CASE_FIELDS,
    COMMON_INCIDENT_FIELDS,
    EXECUTIVE_FIELDS,
    FORBIDDEN_EXPORT_KEYS,
    REPORT_FIELDS_BY_TYPE,
    REPORT_TYPE_ADVANCED,
    REPORT_TYPE_EXECUTIVE,
    REPORT_TYPE_TECHNICAL,
    TECHNICAL_FIELDS,
    TECHNICAL_INCIDENT_FIELDS,
    assert_export_safe,
    forbidden_keys_present,
    normalize_report_type,
    project_fields,
)


def test_report_profiles_are_explicit_and_distinct():
    assert set(
        REPORT_FIELDS_BY_TYPE
    ) == {
        REPORT_TYPE_EXECUTIVE,
        REPORT_TYPE_TECHNICAL,
        REPORT_TYPE_ADVANCED,
    }

    assert (
        EXECUTIVE_FIELDS
        != TECHNICAL_FIELDS
    )

    assert (
        TECHNICAL_FIELDS
        < ADVANCED_FIELDS
    )


def test_report_type_normalization():
    assert (
        normalize_report_type(
            " Executive "
        )
        == REPORT_TYPE_EXECUTIVE
    )

    assert (
        normalize_report_type(
            "TECHNICAL"
        )
        == REPORT_TYPE_TECHNICAL
    )

    assert (
        normalize_report_type(
            "advanced"
        )
        == REPORT_TYPE_ADVANCED
    )


def test_invalid_report_type_is_rejected():
    try:
        normalize_report_type(
            "raw"
        )
    except ValueError as exc:
        assert str(
            exc
        ) == "Unsupported report type"
    else:
        raise AssertionError(
            "Unsupported report type accepted"
        )


def test_executive_surface_excludes_low_level_fields():
    forbidden = {
        "ip",
        "alerts",
        "timeline",
        "response_actions",
        "evidence",
        "entities",
        "threat_intelligence",
        "hunting",
    }

    assert not (
        EXECUTIVE_FIELDS
        & forbidden
    )


def test_technical_surface_excludes_advanced_intelligence():
    forbidden = {
        "entities",
        "threat_intelligence",
        "hunting",
        "evidence",
    }

    assert not (
        TECHNICAL_FIELDS
        & forbidden
    )


def test_advanced_surface_is_superset_of_technical():
    assert (
        TECHNICAL_FIELDS
        < ADVANCED_FIELDS
    )


def test_common_incident_projection_is_minimal():
    assert "alerts" not in COMMON_INCIDENT_FIELDS
    assert "timeline" not in COMMON_INCIDENT_FIELDS
    assert "response_actions" not in COMMON_INCIDENT_FIELDS
    assert "ip" not in COMMON_INCIDENT_FIELDS


def test_technical_incident_projection_adds_soc_context():
    assert "ip" in TECHNICAL_INCIDENT_FIELDS
    assert "attack_phase" in TECHNICAL_INCIDENT_FIELDS
    assert "timeline" in TECHNICAL_INCIDENT_FIELDS
    assert "response_actions" in TECHNICAL_INCIDENT_FIELDS
    assert "alerts" not in TECHNICAL_INCIDENT_FIELDS


def test_advanced_incident_projection_uses_safe_threat_intel_context():
    assert (
        TECHNICAL_INCIDENT_FIELDS
        < ADVANCED_INCIDENT_FIELDS
    )

    assert (
        ADVANCED_INCIDENT_FIELDS
        - TECHNICAL_INCIDENT_FIELDS
    ) == {
        "threat_intel",
    }

    assert (
        "alerts"
        not in ADVANCED_INCIDENT_FIELDS
    )


def test_campaign_projection_is_explicit():
    assert CAMPAIGN_FIELDS == {
        "id",
        "stage",
        "risk",
        "incidents",
        "tactics",
        "created",
        "updated",
    }


def test_case_projection_defaults_exclude_notes_and_evidence():
    assert "notes" not in CASE_FIELDS
    assert "evidence" not in CASE_FIELDS


def test_advanced_case_projection_explicitly_adds_notes_and_evidence():
    assert (
        CASE_FIELDS
        < ADVANCED_CASE_FIELDS
    )

    assert "notes" in ADVANCED_CASE_FIELDS
    assert "evidence" in ADVANCED_CASE_FIELDS


def test_projection_never_copies_unknown_fields():
    source = {
        "id": "INC-1",
        "severity": "HIGH",
        "internal_note": "PRIVATE",
        "secret": "DO-NOT-EXPORT",
        "debug": "PRIVATE-DEBUG",
    }

    projected = project_fields(
        source,
        COMMON_INCIDENT_FIELDS,
    )

    assert projected == {
        "id": "INC-1",
        "severity": "HIGH",
    }


def test_projection_is_detached():
    source = {
        "id": "INC-1",
        "timeline": [
            {
                "event": "demo",
            }
        ],
    }

    projected = project_fields(
        source,
        TECHNICAL_INCIDENT_FIELDS,
    )

    projected[
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


def test_non_dict_projection_fails_closed():
    assert (
        project_fields(
            None,
            COMMON_INCIDENT_FIELDS,
        )
        == {}
    )

    assert (
        project_fields(
            ["unexpected"],
            COMMON_INCIDENT_FIELDS,
        )
        == {}
    )


def test_forbidden_export_keys_are_not_in_any_allowlist():
    allowlists = (
        EXECUTIVE_FIELDS,
        TECHNICAL_FIELDS,
        ADVANCED_FIELDS,
        COMMON_INCIDENT_FIELDS,
        TECHNICAL_INCIDENT_FIELDS,
        ADVANCED_INCIDENT_FIELDS,
        CAMPAIGN_FIELDS,
        CASE_FIELDS,
        ADVANCED_CASE_FIELDS,
    )

    for allowlist in allowlists:
        assert not (
            allowlist
            & FORBIDDEN_EXPORT_KEYS
        )


def test_nested_forbidden_keys_are_detected():
    payload = {
        "incident": {
            "id": "INC-1",
            "alerts": [
                {
                    "internal_note": (
                        "PRIVATE"
                    ),
                    "raw_event": (
                        "DO-NOT-EXPORT"
                    ),
                }
            ],
        }
    }

    assert (
        forbidden_keys_present(
            payload
        )
        == {
            "internal_note",
            "raw_event",
        }
    )


def test_export_safety_accepts_safe_payload():
    payload = {
        "id": "INC-1",
        "severity": "HIGH",
        "timeline": [
            {
                "event": (
                    "Authentication anomaly"
                )
            }
        ],
    }

    assert (
        assert_export_safe(
            payload
        )
        is payload
    )


def test_export_safety_rejects_nested_secret_fields():
    payload = {
        "incident": {
            "id": "INC-1",
            "debug": {
                "token": "PRIVATE",
            },
        }
    }

    try:
        assert_export_safe(
            payload
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
            "Unsafe report payload accepted"
        )


def test_advanced_incident_uses_real_threat_intel_source():
    assert (
        ADVANCED_INCIDENT_FIELDS
        - TECHNICAL_INCIDENT_FIELDS
    ) == {
        "threat_intel",
    }


def test_safe_threat_intel_contract_is_explicit():
    from engine.presentation.reporting_contract import (
        SAFE_THREAT_INTEL_FIELDS,
    )

    assert SAFE_THREAT_INTEL_FIELDS == {
        "reputation",
        "confidence",
        "country",
        "known_attack",
    }


def test_advanced_campaign_adds_entities_only():
    from engine.presentation.reporting_contract import (
        ADVANCED_CAMPAIGN_FIELDS,
    )

    assert (
        ADVANCED_CAMPAIGN_FIELDS
        - CAMPAIGN_FIELDS
    ) == {
        "entities",
    }


def test_safe_entity_types_are_explicit():
    from engine.presentation.reporting_contract import (
        SAFE_ENTITY_TYPES,
    )

    assert SAFE_ENTITY_TYPES == {
        "ip",
        "user",
        "host",
    }
