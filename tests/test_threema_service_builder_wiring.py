from pathlib import Path

import pytest

import engine.bootstrap.builders.service_builder as sb

from engine.services.notification_policy import (
    NotificationPolicy,
)

from engine.services.threema_notification_adapter import (
    ThreemaNotificationAdapter,
)


DEFAULTS = {
    "NOTIFICATION_THREEMA_ENABLED": False,
    "NOTIFICATION_THREEMA_POLICY_ENABLED": False,
    "NOTIFICATION_THREEMA_GATEWAY_ID": "",
    "NOTIFICATION_THREEMA_API_SECRET": "",
    "NOTIFICATION_THREEMA_PRIVATE_KEY_FILE": "",
    "NOTIFICATION_THREEMA_RECIPIENT_ID": "",
    "NOTIFICATION_THREEMA_RECIPIENT_PUBLIC_KEY": "",
    "NOTIFICATION_THREEMA_TIMEOUT_SECONDS": 5,
    "NOTIFICATION_THREEMA_MAX_MESSAGE_BYTES": 7000,
}


def configure(
    monkeypatch,
    **overrides,
):

    values = dict(
        DEFAULTS
    )

    values.update(
        overrides
    )

    for name, value in values.items():

        monkeypatch.setattr(
            sb,
            name,
            value,
        )


def test_default_adapter_is_completely_inert(
    monkeypatch,
):

    configure(
        monkeypatch
    )

    adapter = (
        sb
        ._build_threema_notification_adapter()
    )

    assert adapter is None


def test_default_policy_is_unchanged(
    monkeypatch,
):

    configure(
        monkeypatch
    )

    policy = (
        sb._build_notification_policy()
    )

    assert isinstance(
        policy,
        NotificationPolicy,
    )

    assert (
        policy.threema_enabled
        is False
    )

    result = policy.evaluate({
        "id": "default",
        "severity": "HIGH",
        "risk_score": 1,
        "alerts": [],
        "response_actions": [],
    })

    assert (
        "threema"
        not in result[
            "channels"
        ]
    )


def test_policy_without_adapter_fails_closed(
    monkeypatch,
):

    configure(
        monkeypatch,
        NOTIFICATION_THREEMA_ENABLED=False,
        NOTIFICATION_THREEMA_POLICY_ENABLED=True,
    )

    with pytest.raises(
        ValueError,
        match=(
            "policy cannot be enabled"
        ),
    ):

        sb._build_notification_policy()


def test_enabled_adapter_requires_all_configuration(
    monkeypatch,
):

    configure(
        monkeypatch,
        NOTIFICATION_THREEMA_ENABLED=True,
    )

    with pytest.raises(
        ValueError,
    ) as captured:

        (
            sb
            ._build_threema_notification_adapter()
        )

    message = str(
        captured.value
    )

    expected = (
        "NOTIFICATION_THREEMA_GATEWAY_ID",
        "NOTIFICATION_THREEMA_API_SECRET",
        "NOTIFICATION_THREEMA_PRIVATE_KEY_FILE",
        "NOTIFICATION_THREEMA_RECIPIENT_ID",
        "NOTIFICATION_THREEMA_RECIPIENT_PUBLIC_KEY",
    )

    for name in expected:

        assert name in message


def test_missing_config_error_never_contains_secret_value(
    monkeypatch,
):

    secret = (
        "PRIVATE-API-SECRET-DO-NOT-LEAK"
    )

    configure(
        monkeypatch,
        NOTIFICATION_THREEMA_ENABLED=True,
        NOTIFICATION_THREEMA_GATEWAY_ID=(
            "*ABC1234"
        ),
        NOTIFICATION_THREEMA_API_SECRET=secret,
    )

    with pytest.raises(
        ValueError,
    ) as captured:

        (
            sb
            ._build_threema_notification_adapter()
        )

    assert (
        secret
        not in str(
            captured.value
        )
    )


def test_enabled_adapter_does_not_open_private_key_file(
    monkeypatch,
    tmp_path,
):

    missing_key = (
        tmp_path
        / "does-not-exist.key"
    )

    assert not missing_key.exists()

    configure(
        monkeypatch,
        NOTIFICATION_THREEMA_ENABLED=True,
        NOTIFICATION_THREEMA_GATEWAY_ID=(
            "*ABC1234"
        ),
        NOTIFICATION_THREEMA_API_SECRET=(
            "TEST-SECRET"
        ),
        NOTIFICATION_THREEMA_PRIVATE_KEY_FILE=(
            str(
                missing_key
            )
        ),
        NOTIFICATION_THREEMA_RECIPIENT_ID=(
            "ABCD1234"
        ),
        NOTIFICATION_THREEMA_RECIPIENT_PUBLIC_KEY=(
            "public:"
            + ("11" * 32)
        ),
    )

    adapter = (
        sb
        ._build_threema_notification_adapter()
    )

    assert isinstance(
        adapter,
        ThreemaNotificationAdapter,
    )

    # Factory construction stores only the path.
    # Actual file validation/loading occurs later
    # in factory.build(), inside delivery.
    assert not missing_key.exists()

    assert (
        adapter
        .connection_factory
        .private_key_file
        == missing_key
    )


def test_builder_and_transport_config_are_wired(
    monkeypatch,
    tmp_path,
):

    key_path = (
        tmp_path
        / "not-opened.key"
    )

    configure(
        monkeypatch,
        NOTIFICATION_THREEMA_ENABLED=True,
        NOTIFICATION_THREEMA_GATEWAY_ID=(
            "*ABC1234"
        ),
        NOTIFICATION_THREEMA_API_SECRET=(
            "TEST-SECRET"
        ),
        NOTIFICATION_THREEMA_PRIVATE_KEY_FILE=(
            str(
                key_path
            )
        ),
        NOTIFICATION_THREEMA_RECIPIENT_ID=(
            "ABCD1234"
        ),
        NOTIFICATION_THREEMA_RECIPIENT_PUBLIC_KEY=(
            "public:"
            + ("22" * 32)
        ),
        NOTIFICATION_THREEMA_TIMEOUT_SECONDS=7,
        NOTIFICATION_THREEMA_MAX_MESSAGE_BYTES=3210,
    )

    adapter = (
        sb
        ._build_threema_notification_adapter()
    )

    assert (
        adapter.message_builder.max_bytes
        == 3210
    )

    assert (
        adapter
        .connection_factory
        .timeout_seconds
        == 7
    )

    assert (
        adapter.recipient_id
        == "ABCD1234"
    )

    assert not key_path.exists()


def test_build_services_source_registers_threema_adapter():

    source = Path(
        "engine/bootstrap/builders/"
        "service_builder.py"
    ).read_text(
        encoding="utf-8",
    )

    required = (
        "_build_notification_policy()",
        "_build_threema_notification_adapter()",
        '"threema"',
        "container.threema_notification_adapter",
    )

    for token in required:

        assert token in source
