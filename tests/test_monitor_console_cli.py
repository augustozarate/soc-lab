from engine.cli.soc_cli import (
    SOCConsole,
)


class IncidentManagerStub:
    pass


class CaseManagerStub:
    pass


class MonitorControllerStub:

    def __init__(self):
        self.calls = 0

    def render(self):
        self.calls += 1

        return {
            "operator": {
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
            },
            "runtime": {},
            "health": {
                "status": "UNKNOWN",
                "reasons": [],
                "snapshot_age_seconds": None,
            },
        }


def make_console(
    controller=None,
):
    return SOCConsole(
        monitor_console_controller=(
            controller
        ),
    )


def test_monitor_command_is_registered():
    console = make_console(
        MonitorControllerStub()
    )

    assert (
        ("monitor", None)
        in console.routes
    )

    assert (
        console.routes[
            ("monitor", None)
        ]
        == console.show_monitor_console
    )


def test_monitor_command_delegates_to_controller():
    controller = (
        MonitorControllerStub()
    )

    console = make_console(
        controller
    )

    result = (
        console.show_monitor_console()
    )

    assert controller.calls == 1

    assert (
        result["health"]["status"]
        == "UNKNOWN"
    )


def test_monitor_command_accepts_cli_shape():
    controller = (
        MonitorControllerStub()
    )

    console = make_console(
        controller
    )

    result = (
        console.show_monitor_console(
            args=[],
            flags={},
            input_data=None,
        )
    )

    assert controller.calls == 1
    assert "runtime" in result


def test_monitor_command_requires_controller():
    console = make_console()

    try:
        console.show_monitor_console()

    except RuntimeError as error:
        assert (
            str(error)
            == "Monitor Console is unavailable"
        )

    else:
        raise AssertionError(
            "RuntimeError was not raised"
        )


def test_operator_command_remains_registered():
    console = make_console()

    assert (
        ("operator", None)
        in console.routes
    )


class QueryMonitorControllerStub:

    def __init__(self):
        self.health_calls = 0
        self.channel_calls = 0
        self.metric_calls = 0

    def query_health(self):
        self.health_calls += 1

        return {
            "status": "HEALTHY",
        }

    def query_channels(self):
        self.channel_calls += 1

        return {
            "local": "READY",
            "email": "DISABLED",
        }

    def query_metrics(self):
        self.metric_calls += 1

        return {
            "uptime": "00:10:00",
            "queue_depth": 2,
        }


def make_query_console():
    controller = (
        QueryMonitorControllerStub()
    )

    console = SOCConsole(
        monitor_console_controller=(
            controller
        ),
    )

    return (
        console,
        controller,
    )


def test_read_only_query_commands_are_registered():
    console, _ = make_query_console()

    assert (
        console.routes[
            ("health", None)
        ]
        == console.show_monitor_health
    )

    assert (
        console.routes[
            ("channels", None)
        ]
        == console.show_monitor_channels
    )

    assert (
        console.routes[
            ("metrics", None)
        ]
        == console.show_monitor_metrics
    )


def test_health_command_delegates_to_monitor_controller():
    console, controller = (
        make_query_console()
    )

    result = (
        console.show_monitor_health()
    )

    assert controller.health_calls == 1

    assert result == {
        "status": "HEALTHY",
    }


def test_channels_command_delegates_to_monitor_controller():
    console, controller = (
        make_query_console()
    )

    result = (
        console.show_monitor_channels()
    )

    assert controller.channel_calls == 1

    assert result["local"] == "READY"


def test_metrics_command_delegates_to_monitor_controller():
    console, controller = (
        make_query_console()
    )

    result = (
        console.show_monitor_metrics()
    )

    assert controller.metric_calls == 1

    assert result["queue_depth"] == 2


class IncidentQueryMonitorControllerStub:

    def __init__(self):
        self.calls = []

    def query_incidents(
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
                "id": "INC-001",
                "severity": (
                    severity
                    or "HIGH"
                ),
            }
        ]


def make_incident_query_console():
    controller = (
        IncidentQueryMonitorControllerStub()
    )

    console = SOCConsole(
        monitor_console_controller=(
            controller
        ),
    )

    return (
        console,
        controller,
    )


def test_incidents_recent_command_is_registered():
    console, _ = (
        make_incident_query_console()
    )

    assert (
        console.routes[
            (
                "incidents",
                "recent",
            )
        ]
        == console.show_recent_incidents
    )


def test_incidents_recent_uses_defaults():
    console, controller = (
        make_incident_query_console()
    )

    result = (
        console.show_recent_incidents(
            args=[],
            flags={},
            input_data=None,
        )
    )

    assert controller.calls == [
        (
            20,
            None,
        )
    ]

    assert result[0]["id"] == (
        "INC-001"
    )


def test_incidents_recent_forwards_limit():
    console, controller = (
        make_incident_query_console()
    )

    console.show_recent_incidents(
        args=[],
        flags={
            "limit": "7",
        },
        input_data=None,
    )

    assert controller.calls == [
        (
            "7",
            None,
        )
    ]


def test_incidents_recent_forwards_severity():
    console, controller = (
        make_incident_query_console()
    )

    console.show_recent_incidents(
        args=[],
        flags={
            "severity": "critical",
        },
        input_data=None,
    )

    assert controller.calls == [
        (
            20,
            "critical",
        )
    ]


def test_incidents_recent_forwards_combined_flags():
    console, controller = (
        make_incident_query_console()
    )

    console.show_recent_incidents(
        args=[],
        flags={
            "severity": "HIGH",
            "limit": "10",
        },
        input_data=None,
    )

    assert controller.calls == [
        (
            "10",
            "HIGH",
        )
    ]


def test_read_only_shortcut_expansion_contract():
    expected = {
        "m": "monitor",
        "h": "health",
        "c": "channels",
        "r": "incidents recent",
        "1": (
            "incidents recent "
            "--severity CRITICAL"
        ),
        "2": (
            "incidents recent "
            "--severity HIGH"
        ),
    }

    for shortcut, command in (
        expected.items()
    ):
        assert (
            SOCConsole
            .expand_read_only_shortcut(
                shortcut
            )
            == command
        )


def test_unknown_shortcut_is_unchanged():
    assert (
        SOCConsole
        .expand_read_only_shortcut(
            "incidents recent --limit 7"
        )
        == (
            "incidents recent "
            "--limit 7"
        )
    )


def test_recent_shortcut_uses_existing_bounded_route(
    capsys,
):
    console, controller = (
        make_incident_query_console()
    )

    console._execute_command(
        "r"
    )

    assert controller.calls == [
        (
            20,
            None,
        )
    ]

    output = capsys.readouterr().out

    assert "INC-001" in output


def test_critical_shortcut_uses_existing_bounded_route(
    capsys,
):
    console, controller = (
        make_incident_query_console()
    )

    console._execute_command(
        "1"
    )

    assert controller.calls == [
        (
            20,
            "CRITICAL",
        )
    ]

    output = capsys.readouterr().out

    assert "CRITICAL" in output


def test_high_shortcut_uses_existing_bounded_route(
    capsys,
):
    console, controller = (
        make_incident_query_console()
    )

    console._execute_command(
        "2"
    )

    assert controller.calls == [
        (
            20,
            "HIGH",
        )
    ]

    output = capsys.readouterr().out

    assert "HIGH" in output


def test_shortcut_can_feed_existing_pipeline(
    capsys,
):
    console, controller = (
        make_incident_query_console()
    )

    console._execute_command(
        "1 | util head 1"
    )

    assert controller.calls == [
        (
            20,
            "CRITICAL",
        )
    ]

    output = capsys.readouterr().out

    assert "INC-001" in output
    assert "CRITICAL" in output


def test_shortcut_expansion_is_first_stage_only():
    console, controller = (
        make_incident_query_console()
    )

    stages = [
        stage.strip()
        for stage in (
            "r | util head 1"
        ).split("|")
    ]

    expanded = []

    for index, stage in enumerate(
        stages
    ):
        if index == 0:
            stage = (
                console
                .expand_read_only_shortcut(
                    stage
                )
            )

        expanded.append(
            stage
        )

    assert expanded == [
        "incidents recent",
        "util head 1",
    ]

    assert controller.calls == []


def test_shortcut_targets_are_read_only():
    from engine.cli.soc_cli import (
        READ_ONLY_SHORTCUTS,
    )

    allowed_prefixes = (
        "monitor",
        "health",
        "channels",
        "incidents recent",
    )

    forbidden = (
        "save",
        "delete",
        "remove",
        "send",
        "dispatch",
        "block",
        "release",
        "acknowledge",
        "enable",
        "disable",
    )

    for target in (
        READ_ONLY_SHORTCUTS.values()
    ):
        assert target.startswith(
            allowed_prefixes
        )

        lowered = target.lower()

        assert not any(
            word in lowered
            for word in forbidden
        )


def test_monitor_command_does_not_print_raw_snapshot(
    capsys,
):
    from engine.cli.command_parser import (
        CommandParser,
    )
    from engine.cli.soc_cli import (
        COMMAND_TREE,
        SOCConsole,
    )
    from engine.presentation.monitor_console_controller import (
        MonitorConsoleController,
    )

    class ReadModel:

        def snapshot(
            self,
            incident_limit=10,
        ):
            return {
                "operator": {
                    "summary": {},
                    "incidents": [
                        {
                            "id": "INC-001",
                            "severity": "CRITICAL",
                            "internal_note": (
                                "SHOULD_NOT_PRINT_RAW"
                            ),
                        },
                    ],
                },
                "runtime": {},
                "health": {},
                "channels": {},
            }

    class Renderer:

        def render(
            self,
            snapshot,
        ):
            print(
                "[RENDERED MONITOR]"
            )

    monitor_controller = (
        MonitorConsoleController(
            read_model=ReadModel(),
            renderer=Renderer(),
        )
    )

    console = SOCConsole.__new__(
        SOCConsole
    )

    console.monitor_console_controller = (
        monitor_controller
    )

    console.parser = CommandParser(
        COMMAND_TREE
    )

    console.routes = {
        (
            "monitor",
            None,
        ): console.show_monitor_console,
    }

    console._execute_command(
        "monitor"
    )

    output = (
        capsys
        .readouterr()
        .out
    )

    assert (
        "[RENDERED MONITOR]"
        in output
    )

    assert (
        "SHOULD_NOT_PRINT_RAW"
        not in output
    )

    assert (
        "'operator'"
        not in output
    )


def test_unknown_command_gets_suggestion_without_internal_error(
    capsys,
):
    from engine.cli.command_parser import (
        CommandParser,
    )
    from engine.cli.soc_cli import (
        COMMAND_TREE,
        SOCConsole,
    )

    console = SOCConsole.__new__(
        SOCConsole
    )

    console.parser = CommandParser(
        COMMAND_TREE
    )

    console.routes = {
        (
            "health",
            None,
        ): lambda *args: None,
    }

    console.handle_command(
        "healht"
    )

    output = (
        capsys
        .readouterr()
        .out
    )

    assert (
        "Unknown command 'healht'"
        in output
    )

    assert (
        "Did you mean 'health'?"
        in output
    )

    assert (
        "Available:"
        not in output
    )


def test_valid_command_internal_failure_is_not_unknown_command(
    capsys,
):
    from engine.cli.command_parser import (
        CommandParser,
    )
    from engine.cli.soc_cli import (
        COMMAND_TREE,
        SOCConsole,
    )

    def broken_route(
        args,
        flags,
        input_data,
    ):
        raise RuntimeError(
            "INTERNAL-SECRET-DETAIL"
        )

    console = SOCConsole.__new__(
        SOCConsole
    )

    console.parser = CommandParser(
        COMMAND_TREE
    )

    console.routes = {
        (
            "health",
            None,
        ): broken_route,
    }

    console.handle_command(
        "health"
    )

    output = (
        capsys
        .readouterr()
        .out
    )

    assert (
        "[ERROR] Command execution failed"
        in output
    )

    assert (
        "Unknown command"
        not in output
    )

    assert (
        "INTERNAL-SECRET-DETAIL"
        not in output
    )


def test_unknown_command_without_suggestion_is_generic_unknown(
    capsys,
):
    from engine.cli.command_parser import (
        CommandParser,
    )
    from engine.cli.soc_cli import (
        COMMAND_TREE,
        SOCConsole,
    )

    console = SOCConsole.__new__(
        SOCConsole
    )

    console.parser = CommandParser(
        COMMAND_TREE
    )

    console.routes = {
        (
            "health",
            None,
        ): lambda *args: None,
    }

    console.handle_command(
        "totally-unknown"
    )

    output = (
        capsys
        .readouterr()
        .out
    )

    assert (
        "[ERROR] Unknown command "
        "'totally-unknown'."
        in output
    )

    assert (
        "Command execution failed"
        not in output
    )

    assert (
        "Available:"
        not in output
    )


def test_valid_parsed_command_missing_route_is_operational_failure(
    capsys,
):
    from engine.cli.command_parser import (
        CommandParser,
    )
    from engine.cli.soc_cli import (
        COMMAND_TREE,
        SOCConsole,
    )

    console = SOCConsole.__new__(
        SOCConsole
    )

    console.parser = CommandParser(
        COMMAND_TREE
    )

    console.routes = {}

    console.handle_command(
        "health"
    )

    output = (
        capsys
        .readouterr()
        .out
    )

    assert (
        "[ERROR] Command execution failed"
        in output
    )

    assert (
        "Unknown command"
        not in output
    )

    assert (
        "Command not implemented"
        not in output
    )


class RoutedIncidentControllerStub:

    def __init__(self):
        self.calls = []

    def query_incidents(
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
                "id": "INC-001",
                "ip": "10.0.0.1",
                "severity": "HIGH",
                "risk_score": 90,
            },
            {
                "id": "INC-002",
                "ip": "10.0.0.2",
                "severity": "LOW",
                "risk_score": 10,
            },
        ]


class StrictIncidentManager:

    @property
    def incidents(self):
        raise AssertionError(
            "mutable incident state reached"
        )


def make_routed_incident_console():
    controller = (
        RoutedIncidentControllerStub()
    )

    console = SOCConsole(
        monitor_console_controller=(
            controller
        ),
    )

    return (
        console,
        controller,
    )


def test_incidents_list_uses_bounded_controller_route(
    monkeypatch,
):
    console, controller = (
        make_routed_incident_console()
    )

    logged = []

    monkeypatch.setattr(
        "engine.cli.soc_cli.log",
        logged.append,
    )

    result = (
        console.cmd_incidents_list(
            args=[],
            flags={},
            data=None,
        )
    )

    assert controller.calls == [
        (
            100,
            None,
        )
    ]

    assert [
        row["id"]
        for row in result
    ] == [
        "INC-001",
        "INC-002",
    ]

    assert len(logged) == 1

    table = logged[0]

    assert table.row_count == 2

    assert [
        column.header
        for column in table.columns
    ] == [
        "ID",
        "IP",
        "Severity",
        "Risk",
    ]


def test_incidents_search_filters_controller_projection():
    console, controller = (
        make_routed_incident_console()
    )

    result = (
        console.search_incidents(
            args=[
                "severity=HIGH",
            ],
            flags={},
            input_data=None,
        )
    )

    assert controller.calls == [
        (
            100,
            None,
        )
    ]

    assert result == [
        {
            "id": "INC-001",
            "ip": "10.0.0.1",
            "severity": "HIGH",
            "risk_score": 90,
        }
    ]


def test_incidents_list_can_feed_existing_pipeline(
    capsys,
):
    console, controller = (
        make_routed_incident_console()
    )

    console._execute_command(
        "incidents list | util head 1"
    )

    assert controller.calls == [
        (
            100,
            None,
        )
    ]

    output = (
        capsys
        .readouterr()
        .out
    )

    assert "INC-001" in output


class SingleIncidentRouteControllerStub:

    def __init__(
        self,
    ):
        self.calls = []

        self.rows = {
            "INC-001": {
                "id": "INC-001",
                "severity": "HIGH",
                "campaign_id": None,
                "attack_story": {
                    "summary": "story",
                },
            },
            "INC-GRAPH": {
                "id": "INC-GRAPH",
                "severity": "CRITICAL",
            },
        }

    def query_incident(
        self,
        incident_id,
    ):
        self.calls.append(
            incident_id
        )

        return self.rows.get(
            incident_id
        )


class NoGetIncidentManager:

    def get(
        self,
        incident_id,
    ):
        raise AssertionError(
            "IncidentManager.get reached"
        )


def make_single_incident_route_console():
    controller = (
        SingleIncidentRouteControllerStub()
    )

    console = SOCConsole(
        monitor_console_controller=(
            controller
        ),
    )

    return (
        console,
        controller,
    )


def test_show_incident_uses_single_incident_controller(
    capsys,
):
    console, controller = (
        make_single_incident_route_console()
    )

    console.show_incident(
        ["INC-001"],
        {},
        None,
    )

    assert controller.calls == [
        "INC-001"
    ]

    assert (
        '"id": "INC-001"'
        in capsys.readouterr().out
    )


def test_show_incident_missing_result_preserved(
    capsys,
):
    console, controller = (
        make_single_incident_route_console()
    )

    console.show_incident(
        ["INC-MISSING"],
        {},
        None,
    )

    assert controller.calls == [
        "INC-MISSING"
    ]

    assert (
        "Incident not found"
        in capsys.readouterr().out
    )


def test_cmd_story_uses_single_incident_controller(
    monkeypatch,
):
    console, controller = (
        make_single_incident_route_console()
    )

    rendered = []

    monkeypatch.setattr(
        "engine.cli.soc_cli.render_story",
        lambda story: rendered.append(
            story
        ),
    )

    console.cmd_story(
        ["INC-001"],
        {},
        None,
    )

    assert controller.calls == [
        "INC-001"
    ]

    assert rendered == [
        {
            "summary": "story",
        }
    ]


def test_graph_path_uses_single_incident_controller(
    monkeypatch,
):
    console, controller = (
        make_single_incident_route_console()
    )

    class ThreatGraphStub:

        def get_incident_context(
            self,
            incident_id,
        ):
            return {
                "ips": [],
                "campaigns": [],
                "mitre": [],
            }

    console.threat_graph = (
        ThreatGraphStub()
    )

    console.cmd_graph(
        ["INC-GRAPH"],
        {},
        None,
    )

    assert controller.calls == [
        "INC-GRAPH"
    ]
