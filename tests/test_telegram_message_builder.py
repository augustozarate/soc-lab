from copy import deepcopy

from engine.services.telegram_message_builder import (
    TelegramMessageBuilder,
)


def sample():

    plan = {
        "incident_id": (
            "telegram-incident"
        ),
        "severity": "CRITICAL",
        "risk_score": 99.0,
        "dedup_key": (
            "PRIVATE-DEDUP"
        ),
    }

    incident = {
        "id": (
            "telegram-incident"
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
        TelegramMessageBuilder()
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
        "Incident: telegram-incident"
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
        TelegramMessageBuilder()
        .build(
            plan,
            incident,
        )
    )

    forbidden = (
        "PRIVATE-DEDUP",
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
        TelegramMessageBuilder()
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
        "MITRE: T1110"
        in message
    )


def test_builder_does_not_mutate_inputs():

    plan, incident = sample()

    before_plan = deepcopy(
        plan
    )

    before_incident = deepcopy(
        incident
    )

    TelegramMessageBuilder().build(
        plan,
        incident,
    )

    assert plan == before_plan
    assert incident == before_incident


def test_message_is_bounded_deterministically():

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
                    "X" * 100
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

    builder = TelegramMessageBuilder(
        max_chars=500
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

    assert len(
        first
    ) <= 500

    assert first.endswith(
        "[TRUNCATED]"
    )


def test_invalid_length_limit_is_rejected():

    for value in (
        0,
        4097,
        "invalid",
    ):

        try:

            TelegramMessageBuilder(
                max_chars=value
            )

        except ValueError:

            pass

        else:

            raise AssertionError(
                "invalid max_chars accepted"
            )
