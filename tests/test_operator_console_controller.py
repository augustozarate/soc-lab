from engine.presentation.operator_console_controller import (
    OperatorConsoleController,
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
            "summary": {
                "incidents": 1,
                "high_critical": 1,
                "campaigns": 0,
                "max_risk": 0,
            },
            "incidents": [
                {
                    "id": "INC-001",
                    "severity": "HIGH",
                },
            ],
            "campaigns": [],
            "cases": [],
            "recent_events": [
                {
                    "id": "EVT-001",
                },
            ],
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

    controller = OperatorConsoleController(
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

    assert snapshot["summary"]["incidents"] == 1


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


def test_controller_returns_rendered_snapshot():
    (
        controller,
        _,
        renderer,
    ) = make_controller()

    snapshot = controller.render(
        recent_event_limit=3
    )

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
        "summary": {
            "incidents": 1,
            "high_critical": 1,
            "campaigns": 0,
            "max_risk": 0,
        },
        "incidents": [
            {
                "id": "INC-001",
                "severity": "HIGH",
            },
        ],
        "campaigns": [],
        "cases": [],
        "recent_events": [
            {
                "id": "EVT-001",
            },
        ],
    }

    assert (
        renderer.snapshots[0]
        == snapshot
    )


def test_service_builder_constructs_operator_console(
    tmp_path,
    monkeypatch,
):
    from engine.bootstrap.container import (
        Container
    )
    from engine.presentation.operator_console import (
        OperatorConsoleRenderer
    )
    from engine.presentation.operator_console_controller import (
        OperatorConsoleController
    )
    from engine.presentation.operator_read_model import (
        OperatorReadModel
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

    event_cache = []

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
        event_cache=event_cache,
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
        container.operator_read_model,
        OperatorReadModel,
    )

    assert isinstance(
        container.operator_console_renderer,
        OperatorConsoleRenderer,
    )

    assert isinstance(
        container.operator_console_controller,
        OperatorConsoleController,
    )

    assert (
        container.operator_console_controller.read_model
        is container.operator_read_model
    )

    assert (
        container.operator_console_controller.renderer
        is container.operator_console_renderer
    )

    assert (
        container.operator_read_model.event_cache
        is event_cache
    )

    snapshot = (
        container.operator_console_controller
        .read_model
        .snapshot()
    )

    assert list(snapshot) == [
        "summary",
        "incidents",
        "campaigns",
        "cases",
        "recent_events",
    ]

    assert snapshot["summary"] == {
        "incidents": 0,
        "high_critical": 0,
        "campaigns": 0,
        "max_risk": 0,
    }


class SelectiveOperatorReadModel:

    def __init__(self):
        self.case_calls = []
        self.summary_calls = 0
        self.case_source = [
            {
                "id": "CASE-001",
                "incident_id": "INC-001",
                "status": "OPEN",
                "assignee": "analyst",
            }
        ]

    def cases(
        self,
        limit=20,
    ):
        self.case_calls.append(
            limit
        )

        return [
            dict(
                row
            )
            for row in self.case_source
        ]

    def summary(self):
        self.summary_calls += 1

        return {
            "incidents": 137,
            "high_critical": 11,
            "campaigns": 4,
            "max_risk": 91.0,
        }

    def snapshot(
        self,
        recent_event_limit=10,
    ):
        raise AssertionError(
            "full operator snapshot reached"
        )


def make_selective_operator_controller():
    read_model = (
        SelectiveOperatorReadModel()
    )

    controller = (
        OperatorConsoleController(
            read_model=read_model,
            renderer=object(),
        )
    )

    return (
        controller,
        read_model,
    )


def test_query_cases_delegates_to_bounded_read_model():
    controller, read_model = (
        make_selective_operator_controller()
    )

    result = controller.query_cases(
        limit=17
    )

    assert read_model.case_calls == [
        17
    ]

    assert result == [
        {
            "id": "CASE-001",
            "incident_id": "INC-001",
            "status": "OPEN",
            "assignee": "analyst",
        }
    ]


def test_query_cases_uses_safe_default():
    controller, read_model = (
        make_selective_operator_controller()
    )

    controller.query_cases()

    assert read_model.case_calls == [
        20
    ]


def test_query_cases_result_is_detached():
    controller, read_model = (
        make_selective_operator_controller()
    )

    result = controller.query_cases()

    result[0][
        "status"
    ] = "CLOSED"

    assert (
        read_model.case_source[0][
            "status"
        ]
        == "OPEN"
    )


def test_query_summary_delegates_without_full_snapshot():
    controller, read_model = (
        make_selective_operator_controller()
    )

    result = (
        controller.query_summary()
    )

    assert read_model.summary_calls == 1

    assert result == {
        "incidents": 137,
        "high_critical": 11,
        "campaigns": 4,
        "max_risk": 91.0,
    }


def test_query_summary_result_is_detached():
    controller, read_model = (
        make_selective_operator_controller()
    )

    result = (
        controller.query_summary()
    )

    result[
        "incidents"
    ] = 0

    fresh = (
        controller.query_summary()
    )

    assert (
        fresh[
            "incidents"
        ]
        == 137
    )
