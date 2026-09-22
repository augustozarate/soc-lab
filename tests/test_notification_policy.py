from copy import deepcopy

from engine.services.notification_policy import (
    NotificationPolicy,
)


def incident(
    severity,
    risk_score=0,
):

    return {
        "id": "incident-07",
        "ip": "192.168.20.130",
        "severity": severity,
        "risk_score": risk_score,
        "alerts": [
            {
                "rule_id": "WIN_FAILED_LOGIN",
                "type": "FAILED LOGIN",
                "ip": "192.168.20.130",
                "mitre": {
                    "technique_id": "T1110",
                },
            }
        ],
        "response_actions": [],
    }


def test_critical_routes_to_all_initial_channels():

    policy = NotificationPolicy()

    result = policy.evaluate(
        incident(
            "CRITICAL",
            95,
        )
    )

    assert result is not None

    assert result["incident_id"] == (
        "incident-07"
    )

    assert result["severity"] == (
        "CRITICAL"
    )

    assert result["priority"] == (
        "CRITICAL"
    )

    assert result["channels"] == [
        "local",
        "email",
        "telegram",
        "webhook",
    ]


def test_high_routes_to_operational_channels():

    result = NotificationPolicy().evaluate(
        incident(
            "HIGH",
            80,
        )
    )

    assert result["channels"] == [
        "local",
        "email",
        "telegram",
    ]


def test_medium_routes_to_local_only():

    result = NotificationPolicy().evaluate(
        incident(
            "MEDIUM",
            50,
        )
    )

    assert result["channels"] == [
        "local",
    ]


def test_low_does_not_create_notification_plan():

    result = NotificationPolicy().evaluate(
        incident(
            "LOW",
            10,
        )
    )

    assert result is None


def test_unknown_severity_does_not_notify():

    result = NotificationPolicy().evaluate(
        incident(
            "UNKNOWN",
            20,
        )
    )

    assert result is None


def test_missing_incident_id_is_ignored():

    data = incident(
        "HIGH"
    )

    data.pop(
        "id"
    )

    assert (
        NotificationPolicy().evaluate(
            data
        )
        is None
    )


def test_policy_does_not_mutate_incident():

    data = incident(
        "CRITICAL",
        97,
    )

    original = deepcopy(
        data
    )

    NotificationPolicy().evaluate(
        data
    )

    assert data == original


def test_dedup_key_is_deterministic():

    policy = NotificationPolicy()

    data = incident(
        "HIGH",
        82,
    )

    first = policy.evaluate(
        data
    )

    second = policy.evaluate(
        deepcopy(
            data
        )
    )

    assert (
        first["dedup_key"]
        == second["dedup_key"]
    )

    assert first[
        "dedup_key"
    ].startswith(
        "notification:incident-07:"
    )


def test_dedup_key_changes_when_response_state_changes():

    policy = NotificationPolicy()

    data = incident(
        "HIGH",
        82,
    )

    before = policy.evaluate(
        data
    )

    data["response_actions"].append({
        "type": "BLOCK_IP",
        "target": "192.168.20.130",
        "status": "SUCCESS",
        "execution_mode": "ENFORCED",
        "backend": "windows_firewall",
    })

    after = policy.evaluate(
        data
    )

    assert (
        before["dedup_key"]
        != after["dedup_key"]
    )


def test_event_type_participates_in_dedup_identity():

    policy = NotificationPolicy()

    data = incident(
        "HIGH",
        82,
    )

    persisted = policy.evaluate(
        data,
        event_type="incident_persisted",
    )

    response = policy.evaluate(
        data,
        event_type="response_executed",
    )

    assert (
        persisted["dedup_key"]
        != response["dedup_key"]
    )


def test_risk_score_is_normalized_without_mutation():

    data = incident(
        "HIGH",
        "88",
    )

    result = NotificationPolicy().evaluate(
        data
    )

    assert (
        result["risk_score"]
        == 88.0
    )

    assert (
        data["risk_score"]
        == "88"
    )


def test_invalid_risk_score_falls_back_to_zero():

    result = NotificationPolicy().evaluate(
        incident(
            "MEDIUM",
            "not-a-number",
        )
    )

    assert (
        result["risk_score"]
        == 0.0
    )


def test_alert_order_does_not_change_dedup_key():

    policy = NotificationPolicy()

    data = {
        "id": "incident-order-alerts",
        "severity": "HIGH",
        "risk_score": 82,
        "alerts": [
            {
                "rule_id": "RULE-A",
                "ip": "192.168.20.130",
                "mitre": {
                    "technique_id": "T1110",
                },
            },
            {
                "rule_id": "RULE-B",
                "ip": "192.168.20.130",
                "mitre": {
                    "technique_id": "T1021",
                },
            },
        ],
        "response_actions": [],
    }

    first = policy.evaluate(
        data
    )

    reordered = deepcopy(
        data
    )

    reordered["alerts"] = list(
        reversed(
            reordered["alerts"]
        )
    )

    second = policy.evaluate(
        reordered
    )

    assert (
        first["dedup_key"]
        == second["dedup_key"]
    )


def test_response_action_order_does_not_change_dedup_key():

    policy = NotificationPolicy()

    data = {
        "id": "incident-order-actions",
        "severity": "CRITICAL",
        "risk_score": 95,
        "alerts": [],
        "response_actions": [
            {
                "type": "BLOCK_IP",
                "target": "192.168.20.130",
                "status": "SUCCESS",
                "execution_mode": "ENFORCED",
                "backend": "windows_firewall",
            },
            {
                "type": "NOTIFY_SOC",
                "target": "SOC_TEAM",
                "status": "SUCCESS",
                "execution_mode": "LOCAL",
                "backend": "console",
            },
        ],
    }

    first = policy.evaluate(
        data
    )

    reordered = deepcopy(
        data
    )

    reordered[
        "response_actions"
    ] = list(
        reversed(
            reordered[
                "response_actions"
            ]
        )
    )

    second = policy.evaluate(
        reordered
    )

    assert (
        first["dedup_key"]
        == second["dedup_key"]
    )


def test_alert_content_change_still_changes_dedup_key():

    policy = NotificationPolicy()

    data = {
        "id": "incident-alert-change",
        "severity": "HIGH",
        "risk_score": 81,
        "alerts": [
            {
                "rule_id": "RULE-A",
                "ip": "192.168.20.130",
                "mitre": {
                    "technique_id": "T1110",
                },
            }
        ],
        "response_actions": [],
    }

    before = policy.evaluate(
        data
    )

    changed = deepcopy(
        data
    )

    changed["alerts"][0][
        "mitre"
    ][
        "technique_id"
    ] = "T1021"

    after = policy.evaluate(
        changed
    )

    assert (
        before["dedup_key"]
        != after["dedup_key"]
    )
