from engine.presentation.incident_query_read_model import (
    IncidentQueryReadModel,
)


class FakeIncidentRepository:

    def __init__(self):
        self.recent_calls = []
        self.severity_calls = []

        self.recent_values = [
            {
                "id": "INC-003",
                "severity": "CRITICAL",
            },
            {
                "id": "INC-002",
                "severity": "HIGH",
            },
        ]

        self.severity_values = [
            {
                "id": "INC-003",
                "severity": "CRITICAL",
            },
        ]

    def list_recent(
        self,
        limit,
    ):
        self.recent_calls.append(
            limit
        )

        return self.recent_values

    def list_recent_by_severity(
        self,
        severity,
        limit,
    ):
        self.severity_calls.append(
            (
                severity,
                limit,
            )
        )

        return self.severity_values


def build_model():
    repository = (
        FakeIncidentRepository()
    )

    model = (
        IncidentQueryReadModel(
            incident_repository=repository
        )
    )

    return (
        model,
        repository,
    )


def test_recent_uses_bounded_repository_query():
    model, repository = (
        build_model()
    )

    incidents = model.recent(
        limit=10
    )

    assert repository.recent_calls == [
        10
    ]

    assert repository.severity_calls == []

    assert [
        incident["id"]
        for incident in incidents
    ] == [
        "INC-003",
        "INC-002",
    ]


def test_recent_by_severity_uses_bounded_query():
    model, repository = (
        build_model()
    )

    incidents = model.recent(
        severity="critical",
        limit=5,
    )

    assert repository.recent_calls == []

    assert repository.severity_calls == [
        (
            "CRITICAL",
            5,
        )
    ]

    assert incidents[0][
        "severity"
    ] == "CRITICAL"


def test_supported_severities_are_normalized():
    model, repository = (
        build_model()
    )

    for severity in (
        "low",
        " Medium ",
        "HIGH",
        "critical",
    ):
        model.recent(
            severity=severity,
            limit=1,
        )

    assert repository.severity_calls == [
        ("LOW", 1),
        ("MEDIUM", 1),
        ("HIGH", 1),
        ("CRITICAL", 1),
    ]


def test_unknown_severity_fails_closed():
    model, repository = (
        build_model()
    )

    result = model.recent(
        severity="custom",
        limit=10,
    )

    assert result == []

    assert repository.recent_calls == []
    assert repository.severity_calls == []


def test_zero_and_negative_limits_are_safe():
    model, repository = (
        build_model()
    )

    model.recent(
        limit=0
    )

    model.recent(
        limit=-100
    )

    assert repository.recent_calls == [
        0,
        0,
    ]


def test_invalid_limit_uses_default():
    model, repository = (
        build_model()
    )

    model.recent(
        limit="invalid"
    )

    assert repository.recent_calls == [
        20
    ]


def test_limit_is_hard_capped():
    model, repository = (
        build_model()
    )

    model.recent(
        limit=999999
    )

    assert repository.recent_calls == [
        100
    ]


def test_results_are_detached_from_repository():
    model, repository = (
        build_model()
    )

    result = model.recent(
        limit=10
    )

    result[0][
        "severity"
    ] = "LOW"

    assert (
        repository.recent_values[
            0
        ]["severity"]
        == "CRITICAL"
    )


def test_public_surface_is_read_only():
    model, _ = build_model()

    forbidden = (
        "save",
        "write",
        "update",
        "delete",
        "remove",
        "dispatch",
        "send",
        "execute",
        "close",
        "acknowledge",
    )

    for name in forbidden:
        assert not hasattr(
            model,
            name,
        )


def test_query_surface_is_bounded():
    assert (
        IncidentQueryReadModel
        .DEFAULT_LIMIT
        == 20
    )

    assert (
        IncidentQueryReadModel
        .MAX_LIMIT
        == 100
    )

    assert (
        IncidentQueryReadModel
        .VALID_SEVERITIES
        == (
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
        )
    )


def test_container_constructs_incident_query_read_model(
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

    assert isinstance(
        container.incident_query_read_model,
        IncidentQueryReadModel,
    )

    assert (
        container
        .incident_query_read_model
        .incident_repository
        is container.incident_repository
    )

    assert (
        container
        .incident_query_read_model
        .recent(
            limit=10
        )
        == []
    )


class SingleIncidentRepositoryStub:

    def __init__(self):
        self.get_calls = []
        self.source = {
            "id": "INC-GET-001",
            "severity": "HIGH",
            "timeline": [
                {
                    "time": "2026-01-01T00:00:00",
                    "event": "TEST",
                }
            ],
        }

    def get(
        self,
        incident_id,
    ):
        self.get_calls.append(
            incident_id
        )

        if (
            incident_id
            != self.source["id"]
        ):
            return None

        return self.source


def build_single_incident_model():
    repository = (
        SingleIncidentRepositoryStub()
    )

    model = (
        IncidentQueryReadModel(
            incident_repository=repository
        )
    )

    return (
        model,
        repository,
    )


def test_get_delegates_to_repository_by_id():
    model, repository = (
        build_single_incident_model()
    )

    result = model.get(
        "INC-GET-001"
    )

    assert repository.get_calls == [
        "INC-GET-001"
    ]

    assert result == {
        "id": "INC-GET-001",
        "severity": "HIGH",
        "timeline": [
            {
                "time": "2026-01-01T00:00:00",
                "event": "TEST",
            }
        ],
    }


def test_get_returns_none_for_missing_incident():
    model, repository = (
        build_single_incident_model()
    )

    result = model.get(
        "INC-MISSING"
    )

    assert repository.get_calls == [
        "INC-MISSING"
    ]

    assert result is None


def test_get_result_is_detached_from_repository():
    model, repository = (
        build_single_incident_model()
    )

    result = model.get(
        "INC-GET-001"
    )

    result["severity"] = "LOW"

    result["timeline"][0][
        "event"
    ] = "MUTATED"

    assert (
        repository.source[
            "severity"
        ]
        == "HIGH"
    )

    assert (
        repository.source[
            "timeline"
        ][0]["event"]
        == "TEST"
    )
