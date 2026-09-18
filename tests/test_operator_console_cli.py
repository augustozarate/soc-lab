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
