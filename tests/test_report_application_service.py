from copy import deepcopy
from pathlib import Path

from engine.presentation.report_application_service import (
    ReportApplicationService,
)


class BuilderStub:

    def __init__(
        self,
        document=None,
    ):
        self.document = (
            deepcopy(
                document
            )
            if document is not None
            else {
                "report_type": "technical",
                "generated_at": "now",
            }
        )

        self.calls = []

    def build(
        self,
        **kwargs,
    ):
        self.calls.append(
            deepcopy(
                kwargs
            )
        )

        return deepcopy(
            self.document
        )


class RendererStub:

    def __init__(
        self,
        content="rendered-report\n",
    ):
        self.content = content
        self.calls = []

    def render(
        self,
        document,
        output_format,
    ):
        self.calls.append(
            {
                "document": deepcopy(
                    document
                ),
                "output_format": (
                    output_format
                ),
            }
        )

        return self.content


class ExporterStub:

    def __init__(
        self,
        result=None,
    ):
        self.result = (
            result
            or Path(
                "/safe/reports/report.json"
            )
        )

        self.calls = []

    def export(
        self,
        content,
        output_format,
        basename,
    ):
        self.calls.append(
            {
                "content": content,
                "output_format": (
                    output_format
                ),
                "basename": basename,
            }
        )

        return self.result


def make_service():
    builder = BuilderStub()
    renderer = RendererStub()
    exporter = ExporterStub()

    service = ReportApplicationService(
        document_builder=builder,
        renderer=renderer,
        exporter=exporter,
    )

    return (
        service,
        builder,
        renderer,
        exporter,
    )


def test_render_builds_document_once():
    (
        service,
        builder,
        renderer,
        exporter,
    ) = make_service()

    result = service.render(
        report_type="technical",
        output_format="json",
    )

    assert result == (
        "rendered-report\n"
    )

    assert len(
        builder.calls
    ) == 1

    assert len(
        renderer.calls
    ) == 1

    assert exporter.calls == []


def test_render_forwards_report_parameters():
    (
        service,
        builder,
        _renderer,
        _exporter,
    ) = make_service()

    period = {
        "label": "shift-A",
    }

    service.render(
        report_type="advanced",
        output_format="markdown",
        period=period,
        incident_limit=10,
        campaign_limit=7,
        case_limit=4,
    )

    assert builder.calls == [
        {
            "report_type": "advanced",
            "period": {
                "label": "shift-A",
            },
            "incident_limit": 10,
            "campaign_limit": 7,
            "case_limit": 4,
        }
    ]


def test_render_passes_document_to_renderer():
    (
        service,
        _builder,
        renderer,
        _exporter,
    ) = make_service()

    service.render(
        report_type="executive",
        output_format="markdown",
    )

    assert renderer.calls == [
        {
            "document": {
                "report_type": "technical",
                "generated_at": "now",
            },
            "output_format": "markdown",
        }
    ]


def test_export_runs_complete_pipeline_once():
    (
        service,
        builder,
        renderer,
        exporter,
    ) = make_service()

    result = service.export(
        report_type="executive",
        output_format="json",
        basename="executive-shift-a",
    )

    assert result == Path(
        "/safe/reports/report.json"
    )

    assert len(
        builder.calls
    ) == 1

    assert len(
        renderer.calls
    ) == 1

    assert len(
        exporter.calls
    ) == 1


def test_export_forwards_rendered_content():
    (
        service,
        _builder,
        _renderer,
        exporter,
    ) = make_service()

    service.export(
        report_type="technical",
        output_format="markdown",
        basename="technical-report",
    )

    assert exporter.calls == [
        {
            "content": "rendered-report\n",
            "output_format": "markdown",
            "basename": "technical-report",
        }
    ]


def test_export_forwards_limits_to_builder():
    (
        service,
        builder,
        _renderer,
        _exporter,
    ) = make_service()

    service.export(
        report_type="advanced",
        output_format="json",
        basename="advanced-report",
        incident_limit=25,
        campaign_limit=15,
        case_limit=5,
    )

    assert builder.calls == [
        {
            "report_type": "advanced",
            "period": None,
            "incident_limit": 25,
            "campaign_limit": 15,
            "case_limit": 5,
        }
    ]


def test_service_does_not_mutate_period():
    (
        service,
        _builder,
        _renderer,
        _exporter,
    ) = make_service()

    period = {
        "label": "shift-A",
        "window": {
            "hours": 8,
        },
    }

    original = deepcopy(
        period
    )

    service.render(
        report_type="technical",
        output_format="json",
        period=period,
    )

    assert period == original


def test_builder_error_propagates_without_render_or_export():

    class FailingBuilder:

        def build(
            self,
            **kwargs,
        ):
            raise ValueError(
                "builder failed"
            )

    renderer = RendererStub()
    exporter = ExporterStub()

    service = ReportApplicationService(
        document_builder=(
            FailingBuilder()
        ),
        renderer=renderer,
        exporter=exporter,
    )

    try:
        service.export(
            report_type="technical",
            output_format="json",
            basename="report",
        )

    except ValueError as exc:
        assert str(
            exc
        ) == "builder failed"

    else:
        raise AssertionError(
            "Builder error suppressed"
        )

    assert renderer.calls == []
    assert exporter.calls == []


def test_renderer_error_prevents_export():

    class FailingRenderer:

        def render(
            self,
            document,
            output_format,
        ):
            raise ValueError(
                "renderer failed"
            )

    exporter = ExporterStub()

    service = ReportApplicationService(
        document_builder=(
            BuilderStub()
        ),
        renderer=(
            FailingRenderer()
        ),
        exporter=exporter,
    )

    try:
        service.export(
            report_type="technical",
            output_format="json",
            basename="report",
        )

    except ValueError as exc:
        assert str(
            exc
        ) == "renderer failed"

    else:
        raise AssertionError(
            "Renderer error suppressed"
        )

    assert exporter.calls == []


def test_exporter_error_propagates():

    class FailingExporter:

        def export(
            self,
            content,
            output_format,
            basename,
        ):
            raise ValueError(
                "exporter failed"
            )

    service = ReportApplicationService(
        document_builder=(
            BuilderStub()
        ),
        renderer=(
            RendererStub()
        ),
        exporter=(
            FailingExporter()
        ),
    )

    try:
        service.export(
            report_type="technical",
            output_format="json",
            basename="report",
        )

    except ValueError as exc:
        assert str(
            exc
        ) == "exporter failed"

    else:
        raise AssertionError(
            "Exporter error suppressed"
        )
