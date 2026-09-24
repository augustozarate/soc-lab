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
        incident_manager=(
            IncidentManagerStub()
        ),
        case_manager=(
            CaseManagerStub()
        ),
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
