import importlib
from pathlib import Path

from engine.services.notification_policy import (
    NotificationPolicy,
)

from engine.services.notification_service import (
    NotificationService,
)


def incident(
    severity,
):

    return {
        "id": (
            "threema-policy-test"
        ),
        "severity": severity,
        "risk_score": 90,
        "alerts": [],
        "response_actions": [],
    }


def test_threema_config_defaults_are_safe():

    config = importlib.import_module(
        "engine.config"
    )

    assert (
        config.NOTIFICATION_THREEMA_ENABLED
        is False
    )

    assert (
        config.NOTIFICATION_THREEMA_POLICY_ENABLED
        is False
    )

    assert (
        config.NOTIFICATION_THREEMA_GATEWAY_ID
        == ""
    )

    assert (
        config.NOTIFICATION_THREEMA_API_SECRET
        == ""
    )

    assert (
        config.NOTIFICATION_THREEMA_PRIVATE_KEY_FILE
        == ""
    )

    assert (
        config.NOTIFICATION_THREEMA_RECIPIENT_ID
        == ""
    )

    assert (
        config.NOTIFICATION_THREEMA_RECIPIENT_PUBLIC_KEY
        == ""
    )

    assert (
        config.NOTIFICATION_THREEMA_TIMEOUT_SECONDS
        == 5
    )

    assert (
        config.NOTIFICATION_THREEMA_MAX_MESSAGE_BYTES
        == 7000
    )

    assert (
        config.NOTIFICATION_RATE_LIMIT_THREEMA
        == 0
    )


def test_default_policy_routing_is_unchanged():

    policy = NotificationPolicy()

    critical = policy.evaluate(
        incident(
            "CRITICAL"
        )
    )

    high = policy.evaluate(
        incident(
            "HIGH"
        )
    )

    medium = policy.evaluate(
        incident(
            "MEDIUM"
        )
    )

    assert critical[
        "channels"
    ] == [
        "local",
        "email",
        "telegram",
        "webhook",
    ]

    assert high[
        "channels"
    ] == [
        "local",
        "email",
        "telegram",
    ]

    assert medium[
        "channels"
    ] == [
        "local",
    ]


def test_explicit_policy_opt_in_adds_threema():

    policy = NotificationPolicy(
        threema_enabled=True
    )

    critical = policy.evaluate(
        incident(
            "CRITICAL"
        )
    )

    high = policy.evaluate(
        incident(
            "HIGH"
        )
    )

    medium = policy.evaluate(
        incident(
            "MEDIUM"
        )
    )

    assert critical[
        "channels"
    ] == [
        "local",
        "email",
        "telegram",
        "webhook",
        "threema",
    ]

    assert high[
        "channels"
    ] == [
        "local",
        "email",
        "telegram",
        "threema",
    ]

    assert medium[
        "channels"
    ] == [
        "local",
    ]


def test_threema_is_bounded_metric_channel():

    service = NotificationService()

    assert (
        service._metric_channel(
            "threema"
        )
        == "threema"
    )

    assert (
        service._metric_channel(
            "untrusted-arbitrary-channel"
        )
        == "other"
    )


def test_repository_builder_registers_threema_limit():

    source = Path(
        "engine/bootstrap/builders/"
        "repository_builder.py"
    ).read_text(
        encoding="utf-8"
    )

    assert (
        "NOTIFICATION_RATE_LIMIT_THREEMA"
        in source
    )

    assert (
        '"threema": ('
        in source
    )


def test_threema_policy_does_not_change_dedup_identity():

    incident_data = incident(
        "HIGH"
    )

    disabled = (
        NotificationPolicy(
            threema_enabled=False
        )
        .evaluate(
            incident_data
        )
    )

    enabled = (
        NotificationPolicy(
            threema_enabled=True
        )
        .evaluate(
            incident_data
        )
    )

    # Channel availability is delivery policy,
    # not semantic incident identity.
    assert (
        disabled[
            "dedup_key"
        ]
        == enabled[
            "dedup_key"
        ]
    )
