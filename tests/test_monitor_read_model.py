from copy import deepcopy

from engine.presentation.monitor_read_model import (
    MonitorReadModel,
)


class FakeMonitorOperatorReadModel:

    def __init__(self):
        self.calls = []

        self.value = {
            "summary": {
                "incidents": 2,
                "high_critical": 1,
                "campaigns": 1,
                "max_risk": 91.0,
            },
            "incidents": [
                {
                    "id": "INC-001",
                    "severity": "CRITICAL",
                },
                {
                    "id": "INC-002",
                    "severity": "LOW",
                },
            ],
            "campaigns": [
                {
                    "id": "CAMP-001",
                    "risk": 91,
                },
            ],
            "cases": [],
            "recent_events": [
                {
                    "id": "EVT-001",
                },
            ],
        }

    def snapshot(
        self,
        incident_limit=10,
    ):
        self.calls.append(
            incident_limit
        )

        return deepcopy(
            self.value
        )


class FakeNotificationChannelReadModel:

    def __init__(
        self,
        snapshot=None,
    ):
        self.calls = 0
        self.source = (
            {
                "local": "READY",
                "email": "DISABLED",
                "telegram": "DISABLED",
                "webhook": "DISABLED",
                "threema": "DISABLED",
            }
            if snapshot is None
            else snapshot
        )

    def snapshot(self):
        self.calls += 1
        return self.source


class FakeRuntimeMetricsReader:

    def __init__(
        self,
        value,
    ):
        self.value = value
        self.calls = 0

    def read(self):
        self.calls += 1

        return deepcopy(
            self.value
        )


def runtime_snapshot():
    return {
        "generated_at": (
            "2026-09-24T12:00:00+00:00"
        ),
        "uptime_seconds": 3661,
        "counters": {
            "events_read_total": 120,
            "alerts_generated_total": 8,
            "tasks_completed_total": 110,
            "task_attempt_failures_total": 2,
            "tasks_deduplicated_total": 4,
        },
        "gauges": {
            "queue_depth": 3,
            "checkpoint_lag_bytes": 1024,
        },
        "observations": {
            "task_latency_seconds": {
                "avg": 0.0125,
            },
        },
    }


def build_model(
    metrics=None,
):
    operator = FakeMonitorOperatorReadModel()

    reader = FakeRuntimeMetricsReader(
        runtime_snapshot()
        if metrics is None
        else metrics
    )

    channels = (
        FakeNotificationChannelReadModel()
    )

    return (
        MonitorReadModel(
            monitor_operator_read_model=operator,
            runtime_metrics_reader=reader,
            notification_channel_read_model=(
                channels
            ),
        ),
        operator,
        reader,
        channels,
    )


def test_snapshot_has_bounded_top_level_contract():
    model, _, _, _ = build_model()

    snapshot = model.snapshot()

    assert list(snapshot) == [
        "operator",
        "runtime",
        "health",
        "channels",
    ]


def test_operator_snapshot_is_forwarded():
    model, operator, _, _ = build_model()

    snapshot = model.snapshot(
        incident_limit=4
    )

    assert operator.calls == [4]

    assert (
        snapshot["operator"]["summary"]
        ["incidents"]
        == 2
    )

    assert (
        snapshot["operator"]["incidents"]
        [0]["id"]
        == "INC-001"
    )


def test_runtime_metrics_are_reduced_to_view():
    model, _, reader, _ = build_model()

    snapshot = model.snapshot()

    assert reader.calls == 1

    assert snapshot["runtime"] == {
        "generated_at": (
            "2026-09-24T12:00:00+00:00"
        ),
        "uptime": "01:01:01",
        "queue_depth": 3,
        "checkpoint_lag": "1.0 KiB",
        "events_read": 120,
        "alerts_generated": 8,
        "tasks_completed": 110,
        "task_attempt_failures": 2,
        "tasks_deduplicated": 4,
        "avg_task_latency": "12.5 ms",
    }


def test_healthy_runtime_is_assessed():
    model, _, _, _ = build_model()

    snapshot = model.snapshot()

    assert (
        snapshot["health"]["status"]
        in {
            "HEALTHY",
            "STALE",
        }
    )

    assert (
        "snapshot_age_seconds"
        in snapshot["health"]
    )


def test_missing_metrics_fail_read_only_safe():
    operator = FakeMonitorOperatorReadModel()

    reader = FakeRuntimeMetricsReader(
        None
    )

    channels = (
        FakeNotificationChannelReadModel()
    )

    model = MonitorReadModel(
        monitor_operator_read_model=operator,
        runtime_metrics_reader=reader,
        notification_channel_read_model=(
            channels
        ),
    )

    snapshot = model.snapshot()

    assert snapshot["health"] == {
        "status": "UNKNOWN",
        "reasons": [
            "runtime metrics unavailable"
        ],
        "snapshot_age_seconds": None,
    }

    assert snapshot["runtime"] == {
        "generated_at": None,
        "uptime": "00:00:00",
        "queue_depth": 0,
        "checkpoint_lag": "0 B",
        "events_read": 0,
        "alerts_generated": 0,
        "tasks_completed": 0,
        "task_attempt_failures": 0,
        "tasks_deduplicated": 0,
        "avg_task_latency": "N/A",
    }


def test_snapshot_is_detached_from_sources():
    model, operator, reader, _ = build_model()

    snapshot = model.snapshot()

    snapshot["operator"][
        "incidents"
    ][0]["severity"] = "LOW"

    snapshot["runtime"][
        "queue_depth"
    ] = 999

    snapshot["health"][
        "status"
    ] = "BROKEN"

    assert (
        operator.value["incidents"]
        [0]["severity"]
        == "CRITICAL"
    )

    assert (
        reader.value["gauges"]
        ["queue_depth"]
        == 3
    )


def test_read_model_exposes_no_write_methods():
    public_methods = {
        name
        for name in dir(
            MonitorReadModel
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
        "block",
        "release",
    }

    assert (
        public_methods
        & forbidden
        == set()
    )


def test_service_builder_constructs_monitor_read_model(
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
    stream_file.write_text("")

    mitre_file = (
        mitre / "attack_mapping.yml"
    )
    mitre_file.write_text("{}\n")

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
            data / "event_reader_checkpoint.json"
        ),
    )

    assert isinstance(
        container.monitor_read_model,
        MonitorReadModel,
    )

    assert (
        container.monitor_read_model
        .monitor_operator_read_model
        is container.monitor_operator_read_model
    )

    assert (
        container.monitor_read_model
        .runtime_metrics_reader
        is container.runtime_metrics_reader
    )


def test_container_monitor_snapshot_is_read_only_safe(
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
    stream_file.write_text("")

    mitre_file = (
        mitre / "attack_mapping.yml"
    )
    mitre_file.write_text("{}\n")

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
            data / "event_reader_checkpoint.json"
        ),
    )

    snapshot = (
        container.monitor_read_model
        .snapshot()
    )

    assert list(snapshot) == [
        "operator",
        "runtime",
        "health",
        "channels",
    ]

    assert (
        snapshot["health"]["status"]
        == "UNKNOWN"
    )


def test_channel_snapshot_is_composed():
    (
        model,
        _,
        _,
        channels,
    ) = build_model()

    snapshot = model.snapshot()

    assert channels.calls == 1

    assert snapshot["channels"] == {
        "local": "READY",
        "email": "DISABLED",
        "telegram": "DISABLED",
        "webhook": "DISABLED",
        "threema": "DISABLED",
    }


def test_channel_snapshot_is_detached_from_source():
    source = {
        "local": "READY",
        "email": "READY",
        "telegram": "DISABLED",
        "webhook": "DISABLED",
        "threema": "INERT",
    }

    operator = FakeMonitorOperatorReadModel()

    reader = FakeRuntimeMetricsReader(
        {
            "generated_at": (
                "2026-09-24T12:00:00+00:00"
            ),
            "uptime_seconds": 1,
            "counters": {},
            "gauges": {},
            "observations": {},
        }
    )

    channels = (
        FakeNotificationChannelReadModel(
            source
        )
    )

    model = MonitorReadModel(
        monitor_operator_read_model=operator,
        runtime_metrics_reader=reader,
        notification_channel_read_model=(
            channels
        ),
    )

    snapshot = model.snapshot()

    snapshot["channels"][
        "email"
    ] = "DISABLED"

    assert source["email"] == "READY"


def test_channels_are_bounded_to_expected_surface():
    model, _, _, _ = build_model()

    snapshot = model.snapshot()

    assert tuple(
        snapshot["channels"]
    ) == (
        "local",
        "email",
        "telegram",
        "webhook",
        "threema",
    )


def test_service_builder_constructs_bounded_monitor_operator_model(
    tmp_path,
):
    from engine.bootstrap.container import (
        Container,
    )
    from engine.presentation.monitor_operator_read_model import (
        MonitorOperatorReadModel,
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
    stream_file.write_text("")

    mitre_file = (
        mitre / "attack_mapping.yml"
    )
    mitre_file.write_text(
        "{}\n"
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
            data / "event_reader_checkpoint.json"
        ),
    )

    assert isinstance(
        container.monitor_operator_read_model,
        MonitorOperatorReadModel,
    )

    assert (
        container.monitor_read_model
        .monitor_operator_read_model
        is container.monitor_operator_read_model
    )

    assert (
        container.operator_console_controller
        .read_model
        is container.operator_read_model
    )


def test_container_monitor_snapshot_does_not_use_legacy_list_all(
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
    stream_file.write_text("")

    mitre_file = (
        mitre / "attack_mapping.yml"
    )
    mitre_file.write_text(
        "{}\n"
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
            data / "event_reader_checkpoint.json"
        ),
    )

    def fail_list_all():
        raise AssertionError(
            "legacy list_all path used"
        )

    container.incident_repository.list_all = (
        fail_list_all
    )

    container.campaign_repository.list_all = (
        fail_list_all
    )

    snapshot = (
        container.monitor_read_model
        .snapshot(
            incident_limit=5
        )
    )

    assert (
        snapshot["operator"]["summary"]
        == {
            "incidents": 0,
            "high_critical": 0,
            "campaigns": 0,
            "max_risk": 0.0,
        }
    )

    assert (
        snapshot["operator"]["incidents"]
        == []
    )


def test_monitor_and_operator_read_models_are_isolated(
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
    stream_file.write_text("")

    mitre_file = (
        mitre / "attack_mapping.yml"
    )
    mitre_file.write_text(
        "{}\n"
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
            data / "event_reader_checkpoint.json"
        ),
    )

    assert (
        container.monitor_operator_read_model
        is not container.operator_read_model
    )

    assert (
        container.monitor_console_controller
        .read_model
        is container.monitor_read_model
    )

    assert (
        container.operator_console_controller
        .read_model
        is container.operator_read_model
    )


def test_health_read_path_does_not_touch_operator_or_channels():
    class Operator:

        def snapshot(
            self,
            incident_limit=10,
        ):
            raise AssertionError(
                "operator snapshot reached"
            )

    class MetricsReader:

        def __init__(self):
            self.calls = 0

        def read(self):
            self.calls += 1

            return {
                "uptime_seconds": 10,
                "queue_depth": 0,
                "checkpoint_lag_bytes": 0,
                "task_latency_ms": 1,
                "events_processed": 0,
                "alerts_processed": 0,
                "tasks_processed": 0,
                "failures": 0,
                "deduplicated": 0,
            }

    class Channels:

        def snapshot(self):
            raise AssertionError(
                "channel snapshot reached"
            )

    reader = MetricsReader()

    model = MonitorReadModel(
        monitor_operator_read_model=(
            Operator()
        ),
        runtime_metrics_reader=reader,
        notification_channel_read_model=(
            Channels()
        ),
    )

    result = model.health()

    assert reader.calls == 1

    assert isinstance(
        result,
        dict,
    )

    assert "status" in result


def test_metrics_read_path_does_not_touch_operator_or_channels():
    class Operator:

        def snapshot(
            self,
            incident_limit=10,
        ):
            raise AssertionError(
                "operator snapshot reached"
            )

    class MetricsReader:

        def __init__(self):
            self.calls = 0

        def read(self):
            self.calls += 1

            return {
                "generated_at": (
                    "2026-09-25T12:00:00+00:00"
                ),
                "uptime_seconds": 42,
                "counters": {
                    "events_read_total": 6,
                    "alerts_generated_total": 7,
                    "tasks_completed_total": 8,
                    "task_attempt_failures_total": 0,
                    "tasks_deduplicated_total": 9,
                },
                "gauges": {
                    "queue_depth": 3,
                    "checkpoint_lag_bytes": 4,
                },
                "observations": {
                    "task_latency_seconds": {
                        "avg": 0.005,
                    },
                },
            }

    class Channels:

        def snapshot(self):
            raise AssertionError(
                "channel snapshot reached"
            )

    reader = MetricsReader()

    model = MonitorReadModel(
        monitor_operator_read_model=(
            Operator()
        ),
        runtime_metrics_reader=reader,
        notification_channel_read_model=(
            Channels()
        ),
    )

    result = model.metrics()

    assert reader.calls == 1

    assert isinstance(
        result,
        dict,
    )

    assert (
        result.get(
            "queue_depth"
        )
        == 3
    )


def test_channels_read_path_does_not_touch_operator_or_runtime():
    class Operator:

        def snapshot(
            self,
            incident_limit=10,
        ):
            raise AssertionError(
                "operator snapshot reached"
            )

    class MetricsReader:

        def read(self):
            raise AssertionError(
                "runtime metrics reached"
            )

    class Channels:

        def __init__(self):
            self.calls = 0

        def snapshot(self):
            self.calls += 1

            return {
                "local": "READY",
            }

    channels = Channels()

    model = MonitorReadModel(
        monitor_operator_read_model=(
            Operator()
        ),
        runtime_metrics_reader=(
            MetricsReader()
        ),
        notification_channel_read_model=(
            channels
        ),
    )

    result = model.channels()

    assert channels.calls == 1

    assert result == {
        "local": "READY",
    }


def test_selective_read_results_are_detached():
    source = {
        "local": "READY",
    }

    class Operator:

        def snapshot(
            self,
            incident_limit=10,
        ):
            return {
                "summary": {},
                "incidents": [],
            }

    class MetricsReader:

        def read(self):
            return {
                "uptime_seconds": 0,
                "queue_depth": 0,
                "checkpoint_lag_bytes": 0,
                "task_latency_ms": None,
                "events_processed": 0,
                "alerts_processed": 0,
                "tasks_processed": 0,
                "failures": 0,
                "deduplicated": 0,
            }

    class Channels:

        def snapshot(self):
            return source

    model = MonitorReadModel(
        monitor_operator_read_model=(
            Operator()
        ),
        runtime_metrics_reader=(
            MetricsReader()
        ),
        notification_channel_read_model=(
            Channels()
        ),
    )

    result = model.channels()

    result["local"] = "MUTATED"

    assert source == {
        "local": "READY",
    }
