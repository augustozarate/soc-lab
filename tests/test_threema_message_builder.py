from copy import deepcopy

from engine.services.threema_message_builder import (
    ThreemaMessageBuilder,
)


def sample():

    plan = {
        "incident_id": (
            "threema-incident"
        ),
        "severity": "CRITICAL",
        "risk_score": 99.0,
        "dedup_key": (
            "PRIVATE-THREEMA-DEDUP"
        ),
    }

    incident = {
        "id": (
            "threema-incident"
        ),
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
                    "PRIVATE-RAW-EVENT"
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
                "debug": (
                    "PRIVATE-DEBUG"
                ),
            }
        ],
        "internal_secret": (
            "PRIVATE-INCIDENT-SECRET"
        ),
    }

    return (
        plan,
        incident,
    )


def test_message_contains_allowlisted_fields():

    plan, incident = sample()

    message = (
        ThreemaMessageBuilder()
        .build(
            plan,
            incident,
        )
    )

    assert (
        "[SOC][CRITICAL]"
        in message
    )

    assert (
        "Incident: threema-incident"
        in message
    )

    assert (
        "Risk: 99.0"
        in message
    )

    assert (
        "Source IP: 192.168.20.130"
        in message
    )

    assert (
        "MITRE: T1110"
        in message
    )

    assert (
        "- WIN_FAILED_LOGIN"
        in message
    )

    assert (
        "- BLOCK_IP | SUCCESS | ENFORCED"
        in message
    )


def test_internal_fields_do_not_leak():

    plan, incident = sample()

    message = (
        ThreemaMessageBuilder()
        .build(
            plan,
            incident,
        )
    )

    forbidden = (
        "PRIVATE-THREEMA-DEDUP",
        "PRIVATE-RAW-EVENT",
        "PRIVATE-DEBUG",
        "PRIVATE-INCIDENT-SECRET",
        "windows_firewall",
    )

    for value in forbidden:

        assert value not in message


def test_duplicate_rules_and_mitre_are_collapsed():

    plan, incident = sample()

    message = (
        ThreemaMessageBuilder()
        .build(
            plan,
            incident,
        )
    )

    assert (
        message.count(
            "- WIN_FAILED_LOGIN"
        )
        == 1
    )

    assert (
        message.count(
            "T1110"
        )
        == 1
    )


def test_builder_does_not_mutate_inputs():

    plan, incident = sample()

    before_plan = deepcopy(
        plan
    )

    before_incident = deepcopy(
        incident
    )

    ThreemaMessageBuilder().build(
        plan,
        incident,
    )

    assert plan == before_plan
    assert incident == before_incident


def test_ascii_message_is_bounded_by_utf8_bytes():

    plan, incident = sample()

    incident[
        "alerts"
    ] = [
        {
            "rule_id": (
                "RULE-"
                + str(index)
                + "-"
                + (
                    "X" * 200
                )
            ),
            "mitre": {
                "technique_id": (
                    "T1110"
                ),
            },
        }
        for index in range(
            100
        )
    ]

    builder = ThreemaMessageBuilder(
        max_bytes=500
    )

    first = builder.build(
        plan,
        incident,
    )

    second = builder.build(
        plan,
        incident,
    )

    assert first == second

    assert (
        len(
            first.encode(
                "utf-8"
            )
        )
        <= 500
    )

    assert first.endswith(
        "[TRUNCATED]"
    )


def test_multibyte_message_bound_is_byte_aware():

    plan, incident = sample()

    plan[
        "incident_id"
    ] = (
        "🔐" * 1000
    )

    builder = ThreemaMessageBuilder(
        max_bytes=257
    )

    message = builder.build(
        plan,
        incident,
    )

    encoded = message.encode(
        "utf-8"
    )

    assert len(
        encoded
    ) <= 257

    assert message.endswith(
        "[TRUNCATED]"
    )

    # If UTF-8 truncation split a code point,
    # build() would not have returned a valid
    # Python Unicode string.
    assert (
        encoded.decode(
            "utf-8"
        )
        == message
    )


def test_invalid_byte_limit_is_rejected():

    invalid = (
        0,
        7001,
        True,
        "invalid",
    )

    for value in invalid:

        try:

            ThreemaMessageBuilder(
                max_bytes=value
            )

        except ValueError:

            pass

        else:

            raise AssertionError(
                "invalid max_bytes accepted"
            )
