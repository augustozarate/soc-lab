from engine.cli.soc_cli import (
    SOCConsole,
)


class IncidentManagerStub:
    pass


class CaseManagerStub:
    pass


class OperatorControllerStub:

    def __init__(self):
        self.calls = 0

    def render(self):
        self.calls += 1

        return {
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


def make_console(
    controller=None,
):
    return SOCConsole(
        incident_manager=(
            IncidentManagerStub()
        ),
        case_manager=(
            CaseManagerStub()
        ),
        operator_console_controller=(
            controller
        ),
    )


def test_operator_command_is_registered():
    console = make_console(
        OperatorControllerStub()
    )

    assert (
        ("operator", None)
        in console.routes
    )

    assert (
        console.routes[
            ("operator", None)
        ]
        == console.show_operator_console
    )


def test_operator_command_delegates_to_controller():
    controller = (
        OperatorControllerStub()
    )

    console = make_console(
        controller
    )

    result = (
        console.show_operator_console()
    )

    assert controller.calls == 1

    assert (
        result["summary"]["incidents"]
        == 0
    )


def test_operator_command_accepts_cli_shape():
    controller = (
        OperatorControllerStub()
    )

    console = make_console(
        controller
    )

    result = (
        console.show_operator_console(
            args=[],
            flags={},
            input_data=None,
        )
    )

    assert controller.calls == 1
    assert "recent_events" in result


def test_operator_command_requires_controller():
    console = make_console()

    try:
        console.show_operator_console()

    except RuntimeError as error:
        assert (
            str(error)
            == "Operator Console is unavailable"
        )

    else:
        raise AssertionError(
            "RuntimeError was not raised"
        )


class RoutedOperatorControllerStub:

    def __init__(self):
        self.case_calls = []
        self.summary_calls = 0

    def query_cases(
        self,
        limit=20,
    ):
        self.case_calls.append(
            limit
        )

        return [
            {
                "id": "CASE-001",
                "incident_id": "INC-001",
                "status": "OPEN",
                "assignee": "analyst",
            }
        ]

    def query_summary(self):
        self.summary_calls += 1

        return {
            "incidents": 137,
            "high_critical": 11,
            "campaigns": 4,
            "max_risk": 91.0,
        }


class StrictCaseManager:

    @property
    def cases(self):
        raise AssertionError(
            "mutable case state reached"
        )


class StrictIncidentManager:

    @property
    def incidents(self):
        raise AssertionError(
            "mutable incident state reached"
        )


def make_routed_operator_console():
    controller = (
        RoutedOperatorControllerStub()
    )

    console = SOCConsole(
        incident_manager=(
            StrictIncidentManager()
        ),
        case_manager=(
            StrictCaseManager()
        ),
        operator_console_controller=(
            controller
        ),
    )

    return (
        console,
        controller,
    )


def test_case_route_uses_bounded_operator_controller(
    capsys,
):
    console, controller = (
        make_routed_operator_console()
    )

    result = console.list_cases(
        args=[],
        flags={},
        data=None,
    )

    assert controller.case_calls == [
        100
    ]

    assert result == [
        {
            "id": "CASE-001",
            "incident_id": "INC-001",
            "status": "OPEN",
            "assignee": "analyst",
        }
    ]

    output = (
        capsys
        .readouterr()
        .out
    )

    assert "CASE-001" in output
    assert "Incident INC-001" in output
    assert "Status: OPEN" in output
    assert "Analyst: analyst" in output


def test_empty_case_route_preserves_message(
    capsys,
):
    console, controller = (
        make_routed_operator_console()
    )

    controller.query_cases = (
        lambda limit=20: []
    )

    result = console.list_cases(
        args=[],
        flags={},
        data=None,
    )

    assert result is None

    output = (
        capsys
        .readouterr()
        .out
    )

    assert (
        "No cases available"
        in output
    )


def test_util_count_without_pipeline_uses_global_summary():
    console, controller = (
        make_routed_operator_console()
    )

    result = console.count(
        args=[],
        flags={},
        input_data=None,
    )

    assert result == 137
    assert controller.summary_calls == 1


def test_util_count_with_pipeline_preserves_input_semantics():
    console, controller = (
        make_routed_operator_console()
    )

    result = console.count(
        args=[],
        flags={},
        input_data=[
            {"id": 1},
            {"id": 2},
            {"id": 3},
        ],
    )

    assert result == 3
    assert controller.summary_calls == 0
