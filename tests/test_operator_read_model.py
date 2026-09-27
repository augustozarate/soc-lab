from engine.presentation.operator_read_model import (
    OperatorReadModel,
)


class FakeRepository:

    def __init__(self, values):
        self.values = values
        self.recent_calls = []
        self.recent_summary_calls = []
        self.summary_calls = 0
        self.list_all_calls = 0

    def list_recent(
        self,
        limit,
    ):
        self.recent_calls.append(
            limit
        )

        return self.values[
            :limit
        ]

    def list_recent_summaries(
        self,
        limit,
    ):
        self.recent_summary_calls.append(
            limit
        )

        return [
            {
                "id": value.get(
                    "id"
                ),
                "severity": value.get(
                    "severity"
                ),
            }
            for value
            in self.values[
                :limit
            ]
        ]

    def summary_stats(
        self,
    ):
        self.summary_calls += 1

        high_critical = sum(
            1
            for value in self.values
            if str(
                value.get(
                    "severity",
                    "",
                )
            ).upper()
            in {
                "HIGH",
                "CRITICAL",
            }
        )

        risks = []

        for value in self.values:
            try:
                risks.append(
                    float(
                        value.get(
                            "risk",
                            0,
                        )
                    )
                )
            except (
                TypeError,
                ValueError,
            ):
                risks.append(
                    0
                )

        return {
            "incidents": len(
                self.values
            ),
            "high_critical": high_critical,
            "campaigns": len(
                self.values
            ),
            "max_risk": (
                max(
                    risks
                )
                if risks
                else 0
            ),
        }

    def list_all(self):
        self.list_all_calls += 1

        raise AssertionError(
            "Unbounded repository query used"
        )


class FakeCaseManager:

    def __init__(self, values):
        self.values = values
        self.recent_calls = []
        self.list_cases_calls = 0

    def list_recent(
        self,
        limit,
    ):
        self.recent_calls.append(
            limit
        )

        return self.values[
            :limit
        ]

    def list_cases(self):
        self.list_cases_calls += 1

        raise AssertionError(
            "Unbounded case query used"
        )


def build_model():
    incidents = [
        {
            "id": "inc-1",
            "severity": "CRITICAL",
        },
        {
            "id": "inc-2",
            "severity": "high",
        },
        {
            "id": "inc-3",
            "severity": "LOW",
        },
    ]

    campaigns = [
        {
            "id": "camp-1",
            "risk": 40,
        },
        {
            "id": "camp-2",
            "risk": 91,
        },
    ]

    cases = [
        {
            "id": "case-1",
            "status": "NEW",
        }
    ]

    events = [
        {"id": 1},
        {"id": 2},
        {"id": 3},
    ]

    return OperatorReadModel(
        incident_repository=FakeRepository(
            incidents
        ),
        campaign_repository=FakeRepository(
            campaigns
        ),
        case_manager=FakeCaseManager(
            cases
        ),
        event_cache=events,
    )


def test_summary():
    model = build_model()

    assert model.summary() == {
        "incidents": 3,
        "high_critical": 2,
        "campaigns": 2,
        "max_risk": 91.0,
    }


def test_recent_events_are_bounded():
    model = build_model()

    assert model.recent_events(2) == [
        {"id": 2},
        {"id": 3},
    ]

    assert model.recent_events(0) == []


def test_results_are_detached_from_sources():
    model = build_model()

    incidents = model.incidents()
    campaigns = model.campaigns()
    cases = model.cases()
    events = model.recent_events()

    incidents[0]["severity"] = "LOW"
    campaigns[0]["risk"] = 0
    cases[0]["status"] = "CLOSED"
    events[0]["id"] = 999

    assert (
        model.incident_repository
        .values[0]["severity"]
        == "CRITICAL"
    )

    assert (
        model.campaign_repository
        .values[0]["risk"]
        == 40
    )

    assert (
        model.case_manager
        .values[0]["status"]
        == "NEW"
    )

    assert model.event_cache[0]["id"] == 1


def test_invalid_campaign_risk_is_safe():
    model = OperatorReadModel(
        incident_repository=FakeRepository(
            []
        ),
        campaign_repository=FakeRepository(
            [
                {
                    "id": "camp-1",
                    "risk": "invalid",
                }
            ]
        ),
        case_manager=FakeCaseManager(
            []
        ),
        event_cache=[],
    )

    assert model.summary()["max_risk"] == 0


def test_service_builder_constructs_operator_read_model(
    tmp_path,
):
    from engine.bootstrap.container import Container

    stream_file = tmp_path / "stream.jsonl"
    detection_path = tmp_path / "detections"
    mitre_file = tmp_path / "mitre.json"
    dlq_file = tmp_path / "dlq.jsonl"
    db_file = tmp_path / "soc.db"
    monitor_snapshot_file = (
        tmp_path / "monitor_snapshot.json"
    )
    runtime_metrics_file = (
        tmp_path / "runtime_metrics.json"
    )
    checkpoint_file = (
        tmp_path / "checkpoint.json"
    )

    detection_path.mkdir()

    mitre_file.write_text(
        "{}"
    )

    container = Container(
        stream_file=str(stream_file),
        detection_path=str(detection_path),
        mitre_file=str(mitre_file),
        dlq_file=str(dlq_file),
        db_file=str(db_file),
        event_cache=[],
        monitor_snapshot_file=str(
            monitor_snapshot_file
        ),
        runtime_metrics_file=str(
            runtime_metrics_file
        ),
        event_reader_checkpoint_file=str(
            checkpoint_file
        ),
    )

    model = container.operator_read_model

    assert isinstance(
        model,
        OperatorReadModel,
    )

    assert (
        model.incident_repository
        is container.incident_repository
    )

    assert (
        model.campaign_repository
        is container.campaign_repository
    )

    assert (
        model.case_manager
        is container.case_manager
    )

    assert (
        model.event_cache
        is container.event_cache
    )


def test_snapshot_exposes_operator_view():
    model = OperatorReadModel(
        incident_repository=FakeRepository([
            {
                "id": "incident-1",
                "severity": "HIGH",
            },
        ]),
        campaign_repository=FakeRepository([
            {
                "id": "campaign-1",
                "risk": 82,
            },
        ]),
        case_manager=FakeCaseManager([
            {
                "id": "case-1",
                "status": "NEW",
            },
        ]),
        event_cache=[
            {"id": "event-1"},
            {"id": "event-2"},
            {"id": "event-3"},
        ],
    )

    snapshot = model.snapshot(
        recent_event_limit=2
    )

    assert set(snapshot) == {
        "summary",
        "incidents",
        "campaigns",
        "cases",
        "recent_events",
    }

    assert snapshot["summary"] == {
        "incidents": 1,
        "high_critical": 1,
        "campaigns": 1,
        "max_risk": 82.0,
    }

    assert snapshot["incidents"] == [
        {
            "id": "incident-1",
            "severity": "HIGH",
        },
    ]

    assert snapshot["campaigns"] == [
        {
            "id": "campaign-1",
            "risk": 82,
        },
    ]

    assert snapshot["cases"] == [
        {
            "id": "case-1",
            "status": "NEW",
        },
    ]

    assert snapshot["recent_events"] == [
        {"id": "event-2"},
        {"id": "event-3"},
    ]


def test_snapshot_is_detached_from_sources():
    incidents = [
        {
            "id": "incident-1",
            "severity": "HIGH",
        },
    ]

    campaigns = [
        {
            "id": "campaign-1",
            "risk": 55,
        },
    ]

    cases = [
        {
            "id": "case-1",
            "status": "NEW",
        },
    ]

    events = [
        {
            "id": "event-1",
        },
    ]

    model = OperatorReadModel(
        incident_repository=FakeRepository(
            incidents
        ),
        campaign_repository=FakeRepository(
            campaigns
        ),
        case_manager=FakeCaseManager(
            cases
        ),
        event_cache=events,
    )

    snapshot = model.snapshot()

    snapshot["incidents"][0][
        "severity"
    ] = "CRITICAL"

    snapshot["campaigns"][0][
        "risk"
    ] = 100

    snapshot["cases"][0][
        "status"
    ] = "CLOSED"

    snapshot["recent_events"][0][
        "id"
    ] = "changed"

    assert (
        incidents[0]["severity"]
        == "HIGH"
    )

    assert (
        campaigns[0]["risk"]
        == 55
    )

    assert (
        cases[0]["status"]
        == "NEW"
    )

    assert (
        events[0]["id"]
        == "event-1"
    )


def test_empty_snapshot_contract():
    model = OperatorReadModel(
        incident_repository=FakeRepository([]),
        campaign_repository=FakeRepository([]),
        case_manager=FakeCaseManager([]),
        event_cache=[],
    )

    snapshot = model.snapshot()

    assert snapshot == {
        "summary": {
            "incidents": 0,
            "high_critical": 0,
            "campaigns": 0,
            "max_risk": 0,
        },
        "incidents": [],
        "campaigns": [],
        "cases": [],
        "recent_events": [],
    }


def test_snapshot_recent_event_limit():
    model = OperatorReadModel(
        incident_repository=FakeRepository([]),
        campaign_repository=FakeRepository([]),
        case_manager=FakeCaseManager([]),
        event_cache=[
            {"id": "event-1"},
            {"id": "event-2"},
            {"id": "event-3"},
            {"id": "event-4"},
        ],
    )

    snapshot = model.snapshot(
        recent_event_limit=3
    )

    assert snapshot["recent_events"] == [
        {"id": "event-2"},
        {"id": "event-3"},
        {"id": "event-4"},
    ]


def test_snapshots_are_independent():
    incidents = [
        {
            "id": "incident-1",
            "severity": "HIGH",
        },
    ]

    model = OperatorReadModel(
        incident_repository=FakeRepository(
            incidents
        ),
        campaign_repository=FakeRepository([]),
        case_manager=FakeCaseManager([]),
        event_cache=[
            {"id": "event-1"},
        ],
    )

    first = model.snapshot()
    second = model.snapshot()

    assert first is not second

    assert (
        first["incidents"]
        is not second["incidents"]
    )

    assert (
        first["recent_events"]
        is not second["recent_events"]
    )

    first["incidents"][0][
        "severity"
    ] = "CRITICAL"

    first["recent_events"][0][
        "id"
    ] = "modified"

    assert second["incidents"] == [
        {
            "id": "incident-1",
            "severity": "HIGH",
        },
    ]

    assert second["recent_events"] == [
        {
            "id": "event-1",
        },
    ]


def test_snapshot_default_recent_event_bound():
    events = [
        {
            "id": f"event-{index}"
        }
        for index in range(20)
    ]

    model = OperatorReadModel(
        incident_repository=FakeRepository([]),
        campaign_repository=FakeRepository([]),
        case_manager=FakeCaseManager([]),
        event_cache=events,
    )

    snapshot = model.snapshot()

    assert len(
        snapshot["recent_events"]
    ) == 10

    assert snapshot["recent_events"] == (
        events[-10:]
    )


def test_operator_default_queries_are_bounded():
    model = build_model()

    model.snapshot()

    assert (
        model
        .incident_repository
        .recent_summary_calls
        == [
            20
        ]
    )

    assert (
        model
        .campaign_repository
        .recent_calls
        == [
            20
        ]
    )

    assert (
        model
        .case_manager
        .recent_calls
        == [
            20
        ]
    )

    assert (
        model
        .incident_repository
        .list_all_calls
        == 0
    )

    assert (
        model
        .campaign_repository
        .list_all_calls
        == 0
    )

    assert (
        model
        .case_manager
        .list_cases_calls
        == 0
    )


def test_operator_query_limits_are_capped():
    model = build_model()

    model.snapshot(
        incident_limit=9999,
        campaign_limit=9999,
        case_limit=9999,
    )

    assert (
        model
        .incident_repository
        .recent_summary_calls
        == [
            100
        ]
    )

    assert (
        model
        .campaign_repository
        .recent_calls
        == [
            100
        ]
    )

    assert (
        model
        .case_manager
        .recent_calls
        == [
            100
        ]
    )


def test_operator_zero_limits_return_empty_collections():
    model = build_model()

    snapshot = model.snapshot(
        incident_limit=0,
        campaign_limit=0,
        case_limit=0,
    )

    assert snapshot[
        "incidents"
    ] == []

    assert snapshot[
        "campaigns"
    ] == []

    assert snapshot[
        "cases"
    ] == []

    assert (
        model
        .incident_repository
        .recent_summary_calls
        == [
            0
        ]
    )

    assert (
        model
        .campaign_repository
        .recent_calls
        == [
            0
        ]
    )

    assert (
        model
        .case_manager
        .recent_calls
        == [
            0
        ]
    )


def test_operator_summary_uses_repository_aggregates_only():

    class IncidentRepository:

        def __init__(
            self,
        ):
            self.summary_calls = 0

        def summary_stats(
            self,
        ):
            self.summary_calls += 1

            return {
                "incidents": 400,
                "high_critical": 73,
            }

        def list_recent_summaries(
            self,
            limit,
        ):
            raise AssertionError(
                "Summary reached incident rows"
            )

        def list_all(
            self,
        ):
            raise AssertionError(
                "Summary reached unbounded incidents"
            )

    class CampaignRepository:

        def __init__(
            self,
        ):
            self.summary_calls = 0

        def summary_stats(
            self,
        ):
            self.summary_calls += 1

            return {
                "campaigns": 91,
                "max_risk": 97.5,
            }

        def list_recent(
            self,
            limit,
        ):
            raise AssertionError(
                "Summary reached campaign rows"
            )

        def list_all(
            self,
        ):
            raise AssertionError(
                "Summary reached unbounded campaigns"
            )

    incidents = IncidentRepository()
    campaigns = CampaignRepository()

    model = OperatorReadModel(
        incident_repository=incidents,
        campaign_repository=campaigns,
        case_manager=FakeCaseManager(
            []
        ),
        event_cache=[],
    )

    assert model.summary() == {
        "incidents": 400,
        "high_critical": 73,
        "campaigns": 91,
        "max_risk": 97.5,
    }

    assert incidents.summary_calls == 1
    assert campaigns.summary_calls == 1


def test_operator_never_uses_legacy_unbounded_reads():
    model = build_model()

    model.incidents()
    model.campaigns()
    model.cases()
    model.summary()

    assert (
        model
        .incident_repository
        .list_all_calls
        == 0
    )

    assert (
        model
        .campaign_repository
        .list_all_calls
        == 0
    )

    assert (
        model
        .case_manager
        .list_cases_calls
        == 0
    )
