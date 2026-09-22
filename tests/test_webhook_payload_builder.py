from copy import deepcopy

from engine.services.webhook_payload_builder import (
    WebhookPayloadBuilder,
)


def sample():

    plan = {
        "incident_id": "inc-1",
        "event_type": (
            "incident_persisted"
        ),
        "severity": "CRITICAL",
        "risk_score": 94.0,
        "secret": (
            "must-not-leak"
        ),
    }

    incident = {
        "id": "inc-1",
        "ip": "192.168.20.130",
        "severity": "CRITICAL",
        "updated_at": (
            "2026-09-22T12:00:"
            "00+00:00"
        ),
        "alerts": [
            {
                "rule_id": (
                    "WIN_FAILED_LOGIN"
                ),
                "ip": (
                    "192.168.20.130"
                ),
                "mitre": {
                    "technique_id": (
                        "T1110"
                    ),
                },
                "raw_event": (
                    "private evidence"
                ),
            },
            {
                "rule_id": (
                    "WIN_FAILED_LOGIN"
                ),
                "mitre": {
                    "technique_id": (
                        "T1110"
                    ),
                },
            },
        ],
        "response_actions": [
            {
                "type": "BLOCK_IP",
                "target": (
                    "192.168.20.130"
                ),
                "status": "SUCCESS",
                "execution_mode": (
                    "ENFORCED"
                ),
                "backend": (
                    "windows_firewall"
                ),
                "internal_debug": (
                    "do not export"
                ),
            }
        ],
        "internal_secret": (
            "must-not-leak"
        ),
        "evidence": [
            "large internal evidence"
        ],
    }

    return (
        plan,
        incident,
    )


def test_payload_uses_explicit_allowlist():

    plan, incident = sample()

    payload = (
        WebhookPayloadBuilder()
        .build(
            plan,
            incident,
        )
    )

    assert set(
        payload
    ) == {
        "schema_version",
        "event_type",
        "incident_id",
        "severity",
        "risk_score",
        "timestamp",
        "source",
        "detection",
        "mitre",
        "response_actions",
    }

    assert (
        "internal_secret"
        not in payload
    )

    assert (
        "evidence"
        not in payload
    )

    assert (
        "secret"
        not in payload
    )


def test_payload_normalizes_rule_and_mitre_sets():

    plan, incident = sample()

    payload = (
        WebhookPayloadBuilder()
        .build(
            plan,
            incident,
        )
    )

    assert payload[
        "detection"
    ][
        "rule_ids"
    ] == [
        "WIN_FAILED_LOGIN"
    ]

    assert payload[
        "mitre"
    ] == [
        "T1110"
    ]


def test_payload_filters_response_action_fields():

    plan, incident = sample()

    payload = (
        WebhookPayloadBuilder()
        .build(
            plan,
            incident,
        )
    )

    action = payload[
        "response_actions"
    ][0]

    assert set(
        action
    ) == {
        "type",
        "target",
        "status",
        "execution_mode",
        "backend",
    }

    assert (
        "internal_debug"
        not in action
    )


def test_builder_does_not_mutate_inputs():

    plan, incident = sample()

    before_plan = deepcopy(
        plan
    )

    before_incident = deepcopy(
        incident
    )

    WebhookPayloadBuilder().build(
        plan,
        incident,
    )

    assert plan == before_plan

    assert (
        incident
        == before_incident
    )
