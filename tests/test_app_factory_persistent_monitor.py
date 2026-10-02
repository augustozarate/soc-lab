def test_create_app_wires_persistent_monitor_session(
    monkeypatch,
):
    import engine.bootstrap.app_factory as app_factory

    monitor_controller = object()
    persistent_session = object()

    class FakeContainer:

        def __init__(
            self,
            **_kwargs,
        ):
            self.incident_repository = object()
            self.campaign_repository = object()
            self.case_manager = object()

            self.threat_graph = object()
            self.ai_analyst = object()

            self.operator_console_controller = object()
            self.monitor_console_controller = (
                monitor_controller
            )
            self.campaign_console_controller = object()

            self.rule_watcher = object()
            self.scheduler = object()
            self.worker_pool = object()

    class FakeReportReadModel:

        def __init__(
            self,
            **_kwargs,
        ):
            pass

    class FakeReportDocumentBuilder:

        def __init__(
            self,
            **_kwargs,
        ):
            pass

    class FakeReportRenderer:
        pass

    class FakeReportExporter:

        def __init__(
            self,
            *_args,
            **_kwargs,
        ):
            pass

    class FakeReportApplicationService:

        def __init__(
            self,
            **_kwargs,
        ):
            pass

    captured = {}

    class FakeSOCConsole:

        def __init__(
            self,
            **kwargs,
        ):
            captured["cli_kwargs"] = kwargs

    class FakeSOCRuntime:

        def __init__(
            self,
            **kwargs,
        ):
            captured["runtime_kwargs"] = kwargs

    session_calls = []

    def fake_build_persistent_monitor_session(
        controller,
    ):
        session_calls.append(
            controller
        )
        return persistent_session

    monkeypatch.setattr(
        app_factory,
        "Container",
        FakeContainer,
    )
    monkeypatch.setattr(
        app_factory,
        "ReportReadModel",
        FakeReportReadModel,
    )
    monkeypatch.setattr(
        app_factory,
        "ReportDocumentBuilder",
        FakeReportDocumentBuilder,
    )
    monkeypatch.setattr(
        app_factory,
        "ReportRenderer",
        FakeReportRenderer,
    )
    monkeypatch.setattr(
        app_factory,
        "ReportExporter",
        FakeReportExporter,
    )
    monkeypatch.setattr(
        app_factory,
        "ReportApplicationService",
        FakeReportApplicationService,
    )
    monkeypatch.setattr(
        app_factory,
        "SOCConsole",
        FakeSOCConsole,
    )
    monkeypatch.setattr(
        app_factory,
        "SOCRuntime",
        FakeSOCRuntime,
    )
    monkeypatch.setattr(
        app_factory,
        "build_persistent_monitor_session",
        fake_build_persistent_monitor_session,
        raising=False,
    )

    runtime = app_factory.create_app()

    assert isinstance(
        runtime,
        FakeSOCRuntime,
    )

    assert session_calls == [
        monitor_controller
    ]

    assert (
        captured["cli_kwargs"][
            "persistent_monitor_session"
        ]
        is persistent_session
    )

    assert (
        captured["cli_kwargs"][
            "monitor_console_controller"
        ]
        is monitor_controller
    )
