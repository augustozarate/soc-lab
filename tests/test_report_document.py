from copy import deepcopy

from engine.presentation.report_document import (
    ReportDocumentBuilder,
)


class ReadModelStub:

    def __init__(
        self,
        snapshot,
    ):
        self.value = snapshot
        self.calls = []

    def snapshot(
        self,
        **kwargs,
    ):
        self.calls.append(
            deepcopy(
                kwargs
            )
        )

        return deepcopy(
            self.value
        )


def base_snapshot():
    return {
        "summary": {
            "incidents": 1,
            "high_critical": 1,
            "campaigns": 0,
            "max_risk": 88,
        },
        "incidents": [
            {
                "id": "INC-1",
                "severity": "HIGH",
                "status": "OPEN",
                "risk_score": 88,
                "timeline": [],
                "response_actions": [],
            }
        ],
        "campaigns": [],
        "cases": [],
    }


def test_builder_uses_injected_clock():
    read_model = ReadModelStub(
        base_snapshot()
    )

    builder = ReportDocumentBuilder(
        read_model=read_model,
        clock=lambda: (
            "2026-09-26T12:00:00+00:00"
        ),
    )

    report = builder.build(
        "executive"
    )

    assert report[
        "generated_at"
    ] == (
        "2026-09-26T12:00:00+00:00"
    )


def test_builder_uses_default_period():
    builder = ReportDocumentBuilder(
        read_model=ReadModelStub(
            base_snapshot()
        ),
        clock=lambda: "now",
    )

    report = builder.build(
        "technical"
    )

    assert report["period"] == {
        "label": "current-snapshot",
    }


def test_builder_preserves_explicit_period():
    builder = ReportDocumentBuilder(
        read_model=ReadModelStub(
            base_snapshot()
        ),
        clock=lambda: "now",
    )

    period = {
        "label": "shift-A",
        "from": "08:00",
        "to": "16:00",
    }

    report = builder.build(
        "executive",
        period=period,
    )

    assert report[
        "period"
    ] == period


def test_builder_passes_explicit_limits_only():
    read_model = ReadModelStub(
        base_snapshot()
    )

    builder = ReportDocumentBuilder(
        read_model=read_model,
        clock=lambda: "now",
    )

    builder.build(
        "technical",
        incident_limit=25,
        campaign_limit=10,
        case_limit=5,
    )

    assert read_model.calls == [
        {
            "incident_limit": 25,
            "campaign_limit": 10,
            "case_limit": 5,
        }
    ]


def test_builder_leaves_read_model_defaults_intact():
    read_model = ReadModelStub(
        base_snapshot()
    )

    builder = ReportDocumentBuilder(
        read_model=read_model,
        clock=lambda: "now",
    )

    builder.build(
        "technical"
    )

    assert read_model.calls == [
        {}
    ]


def test_builder_supports_all_three_profiles():
    builder = ReportDocumentBuilder(
        read_model=ReadModelStub(
            base_snapshot()
        ),
        clock=lambda: "now",
    )

    assert (
        builder.build(
            "executive"
        )["report_type"]
        == "executive"
    )

    assert (
        builder.build(
            "technical"
        )["report_type"]
        == "technical"
    )

    assert (
        builder.build(
            "advanced"
        )["report_type"]
        == "advanced"
    )


def test_builder_rejects_unknown_profile():
    builder = ReportDocumentBuilder(
        read_model=ReadModelStub(
            base_snapshot()
        ),
        clock=lambda: "now",
    )

    try:
        builder.build(
            "raw"
        )
    except ValueError as exc:
        assert str(
            exc
        ) == "Unsupported report type"
    else:
        raise AssertionError(
            "Unsupported report accepted"
        )


def test_advanced_builder_requests_advanced_snapshot():
    read_model = ReadModelStub(
        base_snapshot()
    )

    builder = ReportDocumentBuilder(
        read_model=read_model,
        clock=lambda: "now",
    )

    builder.build(
        "advanced"
    )

    assert read_model.calls == [
        {
            "advanced": True,
        }
    ]
