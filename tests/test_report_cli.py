from pathlib import Path

from engine.cli.command_parser import (
    CommandParser,
)
from engine.cli.soc_cli import (
    COMMAND_TREE,
    SOCConsole,
)


class IncidentManagerStub:
    pass


class CaseManagerStub:
    pass


class ReportServiceStub:

    def __init__(self):
        self.render_calls = []
        self.export_calls = []

    def render(
        self,
        **kwargs,
    ):
        self.render_calls.append(
            kwargs
        )

        return "RENDERED REPORT"

    def export(
        self,
        **kwargs,
    ):
        self.export_calls.append(
            kwargs
        )

        return Path(
            "/safe/reports/"
            "report.md"
        )


def make_console(
    service=None,
):
    return SOCConsole(
        incident_manager=(
            IncidentManagerStub()
        ),
        case_manager=(
            CaseManagerStub()
        ),
        report_application_service=(
            service
        ),
    )


def test_report_commands_registered_in_tree():
    assert "report" in COMMAND_TREE

    assert COMMAND_TREE[
        "report"
    ] == {
        "render": {},
        "export": {},
    }


def test_report_routes_registered():
    console = make_console(
        ReportServiceStub()
    )

    assert (
        console.routes[
            ("report", "render")
        ]
        == console.render_report
    )

    assert (
        console.routes[
            ("report", "export")
        ]
        == console.export_report
    )


def test_parser_understands_report_render():
    parser = CommandParser(
        COMMAND_TREE
    )

    parsed = parser.parse(
        "report render technical "
        "--format json "
        "--incidents 12"
    )

    assert parsed == {
        "command": "report",
        "subcommand": "render",
        "args": [
            "technical",
        ],
        "flags": {
            "format": "json",
            "incidents": "12",
        },
    }


def test_render_defaults_to_markdown():
    service = ReportServiceStub()
    console = make_console(
        service
    )

    result = console.render_report(
        args=[
            "technical",
        ],
        flags={},
    )

    assert result == (
        "RENDERED REPORT"
    )

    assert service.render_calls == [
        {
            "report_type": "technical",
            "output_format": "markdown",
            "period": None,
            "incident_limit": None,
            "campaign_limit": None,
            "case_limit": None,
        }
    ]


def test_render_forwards_all_flags():
    service = ReportServiceStub()
    console = make_console(
        service
    )

    console.render_report(
        args=[
            "advanced",
        ],
        flags={
            "format": "json",
            "period": "night-shift",
            "incidents": "10",
            "campaigns": "7",
            "cases": "3",
        },
    )

    assert service.render_calls == [
        {
            "report_type": "advanced",
            "output_format": "json",
            "period": {
                "label": "night-shift",
            },
            "incident_limit": 10,
            "campaign_limit": 7,
            "case_limit": 3,
        }
    ]


def test_export_forwards_filename_and_flags():
    service = ReportServiceStub()
    console = make_console(
        service
    )

    result = console.export_report(
        args=[
            "executive",
            "shift-report",
        ],
        flags={
            "format": "json",
            "incidents": "5",
        },
    )

    assert result == (
        "Report exported: "
        "/safe/reports/report.md"
    )

    assert service.export_calls == [
        {
            "report_type": "executive",
            "output_format": "json",
            "basename": "shift-report",
            "period": None,
            "incident_limit": 5,
            "campaign_limit": None,
            "case_limit": None,
        }
    ]


def test_report_requires_service():
    console = make_console()

    try:
        console.render_report(
            args=[
                "technical",
            ],
            flags={},
        )

    except RuntimeError as exc:
        assert str(
            exc
        ) == (
            "Reporting is unavailable"
        )

    else:
        raise AssertionError(
            "Missing service accepted"
        )


def test_render_rejects_missing_report_type():
    console = make_console(
        ReportServiceStub()
    )

    try:
        console.render_report(
            args=[],
            flags={},
        )

    except ValueError as exc:
        assert "Usage:" in str(
            exc
        )

    else:
        raise AssertionError(
            "Missing report type accepted"
        )


def test_export_requires_filename():
    console = make_console(
        ReportServiceStub()
    )

    try:
        console.export_report(
            args=[
                "technical",
            ],
            flags={},
        )

    except ValueError as exc:
        assert str(
            exc
        ) == (
            "Usage: report export "
            "<executive|technical|advanced> "
            "<filename>"
        )

    else:
        raise AssertionError(
            "Missing filename accepted"
        )


def test_invalid_report_type_rejected():
    console = make_console(
        ReportServiceStub()
    )

    try:
        console.render_report(
            args=[
                "raw",
            ],
            flags={},
        )

    except ValueError as exc:
        assert str(
            exc
        ) == (
            "Unsupported report type"
        )

    else:
        raise AssertionError(
            "Invalid report type accepted"
        )


def test_pdf_render_is_rejected_before_service():
    service = ReportServiceStub()
    console = make_console(
        service
    )

    try:
        console.render_report(
            args=[
                "technical",
            ],
            flags={
                "format": "pdf",
            },
        )

    except ValueError as exc:
        assert str(
            exc
        ) == (
            "PDF reports must be exported"
        )

    else:
        raise AssertionError(
            "Interactive PDF render accepted"
        )

    assert service.render_calls == []


def test_invalid_format_rejected_before_service():
    service = ReportServiceStub()
    console = make_console(
        service
    )

    try:
        console.render_report(
            args=[
                "technical",
            ],
            flags={
                "format": "html",
            },
        )

    except ValueError as exc:
        assert str(
            exc
        ) == (
            "Unsupported report format"
        )

    else:
        raise AssertionError(
            "Invalid format accepted"
        )

    assert service.render_calls == []


def test_invalid_limit_rejected():
    service = ReportServiceStub()
    console = make_console(
        service
    )

    try:
        console.render_report(
            args=[
                "technical",
            ],
            flags={
                "incidents": "many",
            },
        )

    except ValueError as exc:
        assert str(
            exc
        ) == (
            "Invalid report incidents limit"
        )

    else:
        raise AssertionError(
            "Invalid limit accepted"
        )

    assert service.render_calls == []


def test_negative_limit_rejected():
    console = make_console(
        ReportServiceStub()
    )

    try:
        console.render_report(
            args=[
                "technical",
            ],
            flags={
                "cases": "-1",
            },
        )

    except ValueError as exc:
        assert str(
            exc
        ) == (
            "Invalid report cases limit"
        )

    else:
        raise AssertionError(
            "Negative limit accepted"
        )


def test_render_rejects_pipeline_input():
    service = ReportServiceStub()
    console = make_console(
        service
    )

    try:
        console.render_report(
            args=[
                "technical",
            ],
            flags={},
            input_data=[
                {
                    "id": "INC-1",
                },
            ],
        )

    except ValueError as exc:
        assert (
            "cannot consume pipeline input"
            in str(
                exc
            )
        )

    else:
        raise AssertionError(
            "Pipeline input accepted"
        )

    assert service.render_calls == []


def test_export_rejects_pipeline_input():
    service = ReportServiceStub()
    console = make_console(
        service
    )

    try:
        console.export_report(
            args=[
                "technical",
                "report",
            ],
            flags={},
            input_data={
                "unsafe": True,
            },
        )

    except ValueError as exc:
        assert (
            "cannot consume pipeline input"
            in str(
                exc
            )
        )

    else:
        raise AssertionError(
            "Pipeline input accepted"
        )

    assert service.export_calls == []


def test_report_cli_does_not_need_managers_for_data_access():
    service = ReportServiceStub()

    console = SOCConsole(
        incident_manager=None,
        case_manager=None,
        report_application_service=(
            service
        ),
    )

    assert (
        console.render_report(
            args=[
                "executive",
            ],
            flags={},
        )
        == "RENDERED REPORT"
    )

    assert len(
        service.render_calls
    ) == 1


def test_pdf_export_is_forwarded_to_service():
    service = ReportServiceStub()
    console = make_console(
        service
    )

    result = console.export_report(
        args=[
            "advanced",
            "soc-report",
        ],
        flags={
            "format": "pdf",
        },
    )

    assert service.export_calls == [
        {
            "report_type": "advanced",
            "output_format": "pdf",
            "basename": "soc-report",
            "period": None,
            "incident_limit": None,
            "campaign_limit": None,
            "case_limit": None,
        }
    ]

    assert result.startswith(
        "Report exported:"
    )
