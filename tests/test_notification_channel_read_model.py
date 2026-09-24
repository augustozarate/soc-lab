from engine.presentation.notification_channel_read_model import (
    NotificationChannelReadModel,
)


def build_model(
    local=True,
    email=False,
    telegram=False,
    webhook=False,
    threema=False,
    threema_policy=False,
):
    return NotificationChannelReadModel(
        local_available=local,
        email_available=email,
        telegram_available=telegram,
        webhook_available=webhook,
        threema_available=threema,
        threema_policy_enabled=(
            threema_policy
        ),
    )


def test_default_safe_channel_snapshot():
    model = build_model()

    assert model.snapshot() == {
        "local": "READY",
        "email": "DISABLED",
        "telegram": "DISABLED",
        "webhook": "DISABLED",
        "threema": "DISABLED",
    }


def test_available_standard_channels_are_ready():
    model = build_model(
        email=True,
        telegram=True,
        webhook=True,
    )

    snapshot = model.snapshot()

    assert snapshot["email"] == "READY"
    assert snapshot["telegram"] == "READY"
    assert snapshot["webhook"] == "READY"


def test_threema_without_adapter_is_disabled():
    model = build_model(
        threema=False,
        threema_policy=True,
    )

    assert (
        model.snapshot()["threema"]
        == "DISABLED"
    )


def test_threema_adapter_without_policy_is_inert():
    model = build_model(
        threema=True,
        threema_policy=False,
    )

    assert (
        model.snapshot()["threema"]
        == "INERT"
    )


def test_threema_with_policy_is_ready():
    model = build_model(
        threema=True,
        threema_policy=True,
    )

    assert (
        model.snapshot()["threema"]
        == "READY"
    )


def test_inputs_are_normalized_to_booleans():
    model = NotificationChannelReadModel(
        local_available=1,
        email_available="yes",
        telegram_available=[],
        webhook_available=None,
        threema_available=object(),
        threema_policy_enabled=0,
    )

    snapshot = model.snapshot()

    assert snapshot == {
        "local": "READY",
        "email": "READY",
        "telegram": "DISABLED",
        "webhook": "DISABLED",
        "threema": "INERT",
    }


def test_channel_order_is_bounded():
    model = build_model()

    assert tuple(
        model.snapshot()
    ) == (
        "local",
        "email",
        "telegram",
        "webhook",
        "threema",
    )

    assert (
        model.CHANNEL_ORDER
        == (
            "local",
            "email",
            "telegram",
            "webhook",
            "threema",
        )
    )


def test_read_model_exposes_no_write_methods():
    public_methods = {
        name
        for name in dir(
            NotificationChannelReadModel
        )
        if not name.startswith("_")
    }

    forbidden = {
        "save",
        "write",
        "update",
        "delete",
        "remove",
        "send",
        "execute",
        "dispatch",
        "block",
        "release",
    }

    assert (
        public_methods
        & forbidden
        == set()
    )


def test_service_builder_constructs_channel_read_model(
    tmp_path,
):
    from engine.bootstrap.container import (
        Container,
    )

    root = tmp_path

    logs = root / "logs"
    data = root / "data"
    detections = root / "detections"
    mitre = root / "mitre"

    logs.mkdir()
    data.mkdir()
    detections.mkdir()
    mitre.mkdir()

    stream_file = (
        logs / "stream.jsonl"
    )

    stream_file.write_text(
        "",
        encoding="utf-8",
    )

    mitre_file = (
        mitre / "attack_mapping.yml"
    )

    mitre_file.write_text(
        "{}\n",
        encoding="utf-8",
    )

    container = Container(
        stream_file=str(
            stream_file
        ),
        detection_path=str(
            detections
        ),
        mitre_file=str(
            mitre_file
        ),
        dlq_file=str(
            logs / "dead_letter.jsonl"
        ),
        db_file=str(
            data / "soc.db"
        ),
        event_cache=[],
        monitor_snapshot_file=str(
            logs / "monitor_snapshot.json"
        ),
        runtime_metrics_file=str(
            logs / "runtime_metrics.json"
        ),
        event_reader_checkpoint_file=str(
            data
            / "event_reader_checkpoint.json"
        ),
    )

    model = (
        container
        .notification_channel_read_model
    )

    assert isinstance(
        model,
        NotificationChannelReadModel,
    )

    snapshot = model.snapshot()

    assert snapshot["local"] == (
        "READY"
        if (
            container.local_notification_adapter
            is not None
        )
        else "DISABLED"
    )

    assert snapshot["email"] == (
        "READY"
        if (
            container.email_notification_adapter
            is not None
        )
        else "DISABLED"
    )

    assert snapshot["telegram"] == (
        "READY"
        if (
            container.telegram_notification_adapter
            is not None
        )
        else "DISABLED"
    )

    assert snapshot["webhook"] == (
        "READY"
        if (
            container.webhook_notification_adapter
            is not None
        )
        else "DISABLED"
    )

    if (
        container.threema_notification_adapter
        is None
    ):
        assert (
            snapshot["threema"]
            == "DISABLED"
        )
    else:
        assert (
            snapshot["threema"]
            in {
                "INERT",
                "READY",
            }
        )
