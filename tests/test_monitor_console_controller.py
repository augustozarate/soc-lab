from engine.presentation.monitor_console_controller import (
    MonitorConsoleController,
)


class FakeReadModel:

    def __init__(self):
        self.calls = []

    def snapshot(
        self,
        recent_event_limit=10,
    ):
        self.calls.append(
            recent_event_limit
        )

        return {
            "operator": {
                "summary": {
                    "incidents": 1,
                    "high_critical": 1,
                    "campaigns": 0,
                    "max_risk": 75,
                },
                "incidents": [
                    {
                        "id": "INC-001",
                        "severity": "HIGH",
                    },
                ],
                "campaigns": [],
                "cases": [],
                "recent_events": [],
            },
            "runtime": {
                "uptime": "00:10:00",
            },
            "health": {
                "status": "HEALTHY",
                "reasons": [],
                "snapshot_age_seconds": 1,
            },
        }


class FakeRenderer:

    def __init__(self):
        self.snapshots = []

    def render(
        self,
        snapshot,
    ):
        self.snapshots.append(
            snapshot
        )


def make_controller():
    read_model = FakeReadModel()
    renderer = FakeRenderer()

    controller = MonitorConsoleController(
        read_model=read_model,
        renderer=renderer,
    )

    return (
        controller,
        read_model,
        renderer,
    )


def test_controller_reads_and_renders_snapshot():
    (
        controller,
        read_model,
        renderer,
    ) = make_controller()

    snapshot = controller.render()

    assert read_model.calls == [10]

    assert renderer.snapshots == [
        snapshot
    ]

    assert (
        snapshot["health"]["status"]
        == "HEALTHY"
    )


def test_controller_forwards_recent_event_limit():
    (
        controller,
        read_model,
        renderer,
    ) = make_controller()

    controller.render(
        recent_event_limit=4
    )

    assert read_model.calls == [4]

    assert len(
        renderer.snapshots
    ) == 1


def test_controller_returns_same_snapshot():
    (
        controller,
        _,
        renderer,
    ) = make_controller()

    snapshot = controller.render()

    assert (
        renderer.snapshots[0]
        is snapshot
    )


def test_controller_does_not_mutate_snapshot():
    (
        controller,
        _,
        renderer,
    ) = make_controller()

    snapshot = controller.render()

    assert snapshot == {
        "operator": {
            "summary": {
                "incidents": 1,
                "high_critical": 1,
                "campaigns": 0,
                "max_risk": 75,
            },
            "incidents": [
                {
                    "id": "INC-001",
                    "severity": "HIGH",
                },
            ],
            "campaigns": [],
            "cases": [],
            "recent_events": [],
        },
        "runtime": {
            "uptime": "00:10:00",
        },
        "health": {
            "status": "HEALTHY",
            "reasons": [],
            "snapshot_age_seconds": 1,
        },
    }


def test_service_builder_constructs_monitor_console(
    tmp_path,
):
    from engine.bootstrap.container import (
        Container,
    )
    from engine.presentation.monitor_console import (
        MonitorConsoleRenderer,
    )
    from engine.presentation.monitor_read_model import (
        MonitorReadModel,
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

    assert isinstance(
        container.monitor_read_model,
        MonitorReadModel,
    )

    assert isinstance(
        container.monitor_console_renderer,
        MonitorConsoleRenderer,
    )

    assert isinstance(
        container.monitor_console_controller,
        MonitorConsoleController,
    )

    assert (
        container.monitor_console_controller
        .read_model
        is container.monitor_read_model
    )

    assert (
        container.monitor_console_controller
        .renderer
        is container.monitor_console_renderer
    )


class QueryReadModel:

    def __init__(self):
        self.calls = []

        self.source = {
            "operator": {},
            "runtime": {
                "uptime": "00:10:00",
                "queue_depth": 2,
                "events_read": 120,
            },
            "health": {
                "status": "HEALTHY",
                "reasons": [],
                "snapshot_age_seconds": 1.0,
            },
            "channels": {
                "local": "READY",
                "email": "DISABLED",
                "telegram": "DISABLED",
                "webhook": "READY",
                "threema": "INERT",
            },
        }

    def snapshot(
        self,
        recent_event_limit=10,
    ):
        self.calls.append(
            recent_event_limit
        )

        return self.source


def make_query_controller():
    read_model = QueryReadModel()

    controller = MonitorConsoleController(
        read_model=read_model,
        renderer=object(),
    )

    return (
        controller,
        read_model,
    )


def test_query_health_returns_health_view():
    controller, read_model = (
        make_query_controller()
    )

    result = controller.query_health()

    assert read_model.calls == [10]

    assert result == {
        "status": "HEALTHY",
        "reasons": [],
        "snapshot_age_seconds": 1.0,
    }


def test_query_channels_returns_channel_view():
    controller, read_model = (
        make_query_controller()
    )

    result = controller.query_channels()

    assert read_model.calls == [10]

    assert result == {
        "local": "READY",
        "email": "DISABLED",
        "telegram": "DISABLED",
        "webhook": "READY",
        "threema": "INERT",
    }


def test_query_metrics_returns_runtime_view():
    controller, read_model = (
        make_query_controller()
    )

    result = controller.query_metrics()

    assert read_model.calls == [10]

    assert result == {
        "uptime": "00:10:00",
        "queue_depth": 2,
        "events_read": 120,
    }


def test_query_results_are_detached():
    controller, read_model = (
        make_query_controller()
    )

    channels = (
        controller.query_channels()
    )

    channels["email"] = "READY"

    assert (
        read_model.source[
            "channels"
        ]["email"]
        == "DISABLED"
    )


class IncidentQueryReadModelStub:

    def __init__(self):
        self.calls = []

    def recent(
        self,
        limit=20,
        severity=None,
    ):
        self.calls.append(
            (
                limit,
                severity,
            )
        )

        return [
            {
                "id": "INC-003",
                "severity": (
                    severity
                    or "CRITICAL"
                ),
            }
        ]


def make_incident_query_controller():
    incident_query = (
        IncidentQueryReadModelStub()
    )

    controller = MonitorConsoleController(
        read_model=QueryReadModel(),
        renderer=object(),
        incident_query_read_model=(
            incident_query
        ),
    )

    return (
        controller,
        incident_query,
    )


def test_query_incidents_delegates_to_bounded_read_model():
    controller, query_model = (
        make_incident_query_controller()
    )

    result = (
        controller.query_incidents(
            limit=10,
            severity="HIGH",
        )
    )

    assert query_model.calls == [
        (
            10,
            "HIGH",
        )
    ]

    assert result == [
        {
            "id": "INC-003",
            "severity": "HIGH",
        }
    ]


def test_query_incidents_uses_safe_defaults():
    controller, query_model = (
        make_incident_query_controller()
    )

    controller.query_incidents()

    assert query_model.calls == [
        (
            20,
            None,
        )
    ]


def test_query_incidents_result_is_detached():
    controller, query_model = (
        make_incident_query_controller()
    )

    result = (
        controller.query_incidents()
    )

    result[0][
        "severity"
    ] = "LOW"

    fresh = (
        controller.query_incidents()
    )

    assert (
        fresh[0]["severity"]
        == "CRITICAL"
    )

    assert len(
        query_model.calls
    ) == 2


def test_query_incidents_requires_query_model():
    controller = MonitorConsoleController(
        read_model=QueryReadModel(),
        renderer=object(),
    )

    try:
        controller.query_incidents()

    except RuntimeError as error:
        assert (
            str(error)
            == (
                "Incident query surface "
                "is unavailable"
            )
        )

    else:
        raise AssertionError(
            "RuntimeError was not raised"
        )
