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
