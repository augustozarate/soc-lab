from engine.services.local_notification_adapter import (
    LocalNotificationAdapter,
)


def test_local_adapter_writes_deterministic_message():

    messages = []

    adapter = LocalNotificationAdapter(
        writer=messages.append
    )

    result = adapter.send(
        {
            "incident_id": "incident-local",
            "severity": "HIGH",
            "risk_score": 82.0,
        },
        {
            "id": "incident-local",
        },
    )

    assert messages == [
        (
            "[SOC NOTIFICATION] "
            "incident=incident-local "
            "severity=HIGH "
            "risk=82.0"
        )
    ]

    assert result == {
        "channel": "local",
        "status": "SUCCESS",
        "backend": "console",
        "incident_id": "incident-local",
    }
