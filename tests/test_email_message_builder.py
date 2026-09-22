from copy import deepcopy

from engine.services.email_message_builder import (
    EmailMessageBuilder,
)


def sample():

    plan = {
        "incident_id": "inc-email-1",
        "event_type": (
            "incident_persisted"
        ),
        "severity": "CRITICAL",
        "risk_score": 97.0,
        "dedup_key": (
            "SECRET-INTERNAL-DEDUP"
        ),
    }

    incident = {
        "id": "inc-email-1",
        "ip": "192.168.20.130",
        "alerts": [
            {
                "rule_id": (
                    "WIN_FAILED_LOGIN"
                ),
                "mitre": {
                    "technique_id": (
                        "T1110"
                    ),
                },
                "raw_event": (
                    "RAW-PRIVATE-EVIDENCE"
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
                    "PRIVATE-DEBUG"
                ),
            }
        ],
        "internal_secret": (
            "PRIVATE-INCIDENT-SECRET"
        ),
        "evidence": [
            "PRIVATE-EVIDENCE"
        ],
    }

    return (
        plan,
        incident,
    )


def builder():

    return EmailMessageBuilder(
        sender=(
            "soc@example.invalid"
        ),
        recipient=(
            "analyst@example.invalid"
        ),
    )


def test_message_headers_are_deterministic():

    plan, incident = sample()

    message = builder().build(
        plan,
        incident,
    )

    assert (
        message["Subject"]
        == (
            "[SOC][CRITICAL] "
            "Incident inc-email-1"
        )
    )

    assert (
        message["From"]
        == "soc@example.invalid"
    )

    assert (
        message["To"]
        == "analyst@example.invalid"
    )


def test_body_contains_allowlisted_soc_fields():

    plan, incident = sample()

    body = builder().build(
        plan,
        incident,
    ).get_content()

    assert (
        "Incident ID: inc-email-1"
        in body
    )

    assert (
        "Severity: CRITICAL"
        in body
    )

    assert (
        "Risk Score: 97.0"
        in body
    )

    assert (
        "Source IP: 192.168.20.130"
        in body
    )

    assert (
        "MITRE: T1110"
        in body
    )

    assert (
        "- WIN_FAILED_LOGIN"
        in body
    )

    assert (
        "- BLOCK_IP | SUCCESS | ENFORCED"
        in body
    )


def test_internal_fields_do_not_leak():

    plan, incident = sample()

    serialized = (
        builder()
        .build(
            plan,
            incident,
        )
        .as_string()
    )

    forbidden = (
        "SECRET-INTERNAL-DEDUP",
        "RAW-PRIVATE-EVIDENCE",
        "PRIVATE-DEBUG",
        "PRIVATE-INCIDENT-SECRET",
        "PRIVATE-EVIDENCE",
        "windows_firewall",
    )

    for value in forbidden:

        assert (
            value
            not in serialized
        )


def test_duplicate_rules_and_mitre_are_collapsed():

    plan, incident = sample()

    body = builder().build(
        plan,
        incident,
    ).get_content()

    assert (
        body.count(
            "- WIN_FAILED_LOGIN"
        )
        == 1
    )

    assert (
        "MITRE: T1110"
        in body
    )


def test_builder_does_not_mutate_inputs():

    plan, incident = sample()

    before_plan = deepcopy(
        plan
    )

    before_incident = deepcopy(
        incident
    )

    builder().build(
        plan,
        incident,
    )

    assert plan == before_plan
    assert incident == before_incident
