import json
from copy import deepcopy

from engine.presentation.report_renderer import (
    ReportRenderer,
)


def executive_document():
    return {
        "report_type": "executive",
        "generated_at": "2026-09-26T12:00:00+00:00",
        "period": {
            "label": "shift-A",
        },
        "summary": {
            "incidents": 3,
            "high_critical": 2,
            "campaigns": 1,
        },
        "risk": {
            "maximum": 95.0,
            "high_critical": 2,
        },
        "critical_incidents": [
            {
                "id": "INC-1",
                "severity": "CRITICAL",
                "status": "OPEN",
                "risk_score": 95,
            }
        ],
        "campaigns": [],
        "response_overview": {
            "cases": 1,
            "open_cases": 1,
        },
        "recommendations": [
            (
                "Prioritize active critical "
                "incident investigation."
            ),
        ],
    }


def technical_document():
    return {
        "report_type": "technical",
        "generated_at": "2026-09-26T12:00:00+00:00",
        "period": {
            "label": "shift-A",
        },
        "summary": {
            "incidents": 1,
        },
        "incidents": [
            {
                "id": "INC-1",
                "severity": "HIGH",
                "status": "OPEN",
                "ip": "192.0.2.10",
            }
        ],
        "campaigns": [],
        "mitre": [
            {
                "tactic": "Credential Access",
                "technique_id": "T1110",
                "technique": "Brute Force",
            }
        ],
        "timeline": [
            {
                "incident_id": "INC-1",
                "time": "10:00",
                "event": "Authentication anomaly",
            }
        ],
        "response_actions": [
            {
                "incident_id": "INC-1",
                "type": "BLOCK_IP",
                "status": "SUCCESS",
            }
        ],
        "operational_status": {
            "source": "report-read-model",
            "state": "READ_ONLY",
        },
    }


def advanced_document():
    document = technical_document()

    document[
        "report_type"
    ] = "advanced"

    document[
        "entities"
    ] = [
        {
            "campaign_id": "CMP-1",
            "type": "ip",
            "value": "192.0.2.10",
        }
    ]

    document[
        "threat_intelligence"
    ] = [
        {
            "incident_id": "INC-1",
            "reputation": "suspicious",
            "confidence": 90,
            "country": "AR",
            "known_attack": True,
        }
    ]

    document[
        "hunting"
    ] = []

    document[
        "evidence"
    ] = [
        {
            "case_id": "CASE-1",
            "incident_id": "INC-1",
            "status": "OPEN",
            "severity": "HIGH",
        }
    ]

    return document


def test_json_renderer_is_deterministic():
    renderer = ReportRenderer()

    document = executive_document()

    first = renderer.render(
        document,
        "json",
    )

    second = renderer.render(
        document,
        "json",
    )

    assert first == second


def test_json_renderer_is_valid_json():
    renderer = ReportRenderer()

    rendered = renderer.render(
        technical_document(),
        "json",
    )

    parsed = json.loads(
        rendered
    )

    assert (
        parsed["report_type"]
        == "technical"
    )


def test_json_renderer_has_stable_sorted_keys():
    renderer = ReportRenderer()

    rendered = renderer.render(
        {
            "report_type": "executive",
            "generated_at": "now",
            "period": {},
            "summary": {},
            "risk": {},
            "critical_incidents": [],
            "campaigns": [],
            "response_overview": {},
            "recommendations": [],
        },
        "json",
    )

    lines = rendered.splitlines()

    assert lines[1].strip().startswith(
        '"campaigns"'
    )


def test_markdown_executive_has_expected_sections():
    renderer = ReportRenderer()

    rendered = renderer.render(
        executive_document(),
        "markdown",
    )

    assert (
        "# SOC Report — EXECUTIVE"
        in rendered
    )

    assert (
        "## Executive Summary"
        in rendered
    )

    assert (
        "## Critical Incidents"
        in rendered
    )

    assert (
        "## Recommendations"
        in rendered
    )


def test_markdown_technical_has_expected_sections():
    renderer = ReportRenderer()

    rendered = renderer.render(
        technical_document(),
        "markdown",
    )

    assert "## Incidents" in rendered
    assert "## MITRE ATT&CK" in rendered
    assert "## Timeline" in rendered
    assert "## Response Actions" in rendered


def test_markdown_advanced_has_expected_sections():
    renderer = ReportRenderer()

    rendered = renderer.render(
        advanced_document(),
        "markdown",
    )

    assert "## Entities" in rendered
    assert "## Threat Intelligence" in rendered
    assert "## Hunting" in rendered
    assert "## Evidence" in rendered


def test_markdown_advanced_renders_real_intelligence():
    renderer = ReportRenderer()

    rendered = renderer.render(
        advanced_document(),
        "markdown",
    )

    assert "CMP-1 | ip | 192.0.2.10" in rendered

    assert (
        "INC-1 | suspicious | "
        "confidence=90 | country=AR"
        in rendered
    )

    assert "## Hunting\n\n- None" in rendered


def test_pdf_renderer_returns_pdf_bytes():
    renderer = ReportRenderer()

    rendered = renderer.render(
        executive_document(),
        "pdf",
    )

    assert isinstance(
        rendered,
        bytes,
    )

    assert rendered.startswith(
        b"%PDF-"
    )

    assert len(rendered) > 500


def test_pdf_renderer_supports_all_report_profiles():
    renderer = ReportRenderer()

    for document in (
        executive_document(),
        technical_document(),
        advanced_document(),
    ):
        rendered = renderer.render(
            document,
            "pdf",
        )

        assert rendered.startswith(
            b"%PDF-"
        )


def test_pdf_renderer_rejects_forbidden_nested_fields():
    renderer = ReportRenderer()

    document = technical_document()

    document[
        "timeline"
    ][0][
        "raw_payload"
    ] = "PRIVATE"

    try:
        renderer.render(
            document,
            "pdf",
        )

    except ValueError as exc:
        assert str(
            exc
        ) == (
            "Report payload contains "
            "forbidden export fields"
        )

    else:
        raise AssertionError(
            "Unsafe document rendered"
        )


def test_renderer_rejects_unsupported_format():
    renderer = ReportRenderer()

    try:
        renderer.render(
            executive_document(),
            "html",
        )

    except ValueError as exc:
        assert str(
            exc
        ) == (
            "Unsupported report format"
        )

    else:
        raise AssertionError(
            "Unsupported format accepted"
        )


def test_renderer_rejects_forbidden_nested_fields():
    renderer = ReportRenderer()

    document = technical_document()

    document[
        "timeline"
    ][0][
        "raw_payload"
    ] = "PRIVATE"

    try:
        renderer.render(
            document,
            "json",
        )
    except ValueError as exc:
        assert str(
            exc
        ) == (
            "Report payload contains "
            "forbidden export fields"
        )
    else:
        raise AssertionError(
            "Unsafe document rendered"
        )


def test_renderer_does_not_mutate_document():
    renderer = ReportRenderer()

    document = advanced_document()
    original = deepcopy(
        document
    )

    renderer.render(
        document,
        "json",
    )

    renderer.render(
        document,
        "markdown",
    )

    assert document == original


def test_markdown_scalar_normalization_removes_newlines():
    renderer = ReportRenderer()

    document = executive_document()

    document[
        "critical_incidents"
    ][0][
        "status"
    ] = "OPEN\nINJECTED"

    rendered = renderer.render(
        document,
        "markdown",
    )

    assert "OPEN INJECTED" in rendered
    assert "OPEN\nINJECTED" not in rendered


def test_json_renderer_preserves_unicode():
    renderer = ReportRenderer()

    document = executive_document()

    document[
        "recommendations"
    ] = [
        "Revisión técnica",
    ]

    rendered = renderer.render(
        document,
        "json",
    )

    assert "Revisión técnica" in rendered
    assert "\\u00f3" not in rendered


def test_markdown_output_has_single_terminal_newline():
    renderer = ReportRenderer()

    rendered = renderer.render(
        executive_document(),
        "markdown",
    )

    assert rendered.endswith(
        "\n"
    )

    assert not rendered.endswith(
        "\n\n"
    )


def test_json_output_has_single_terminal_newline():
    renderer = ReportRenderer()

    rendered = renderer.render(
        executive_document(),
        "json",
    )

    assert rendered.endswith(
        "\n"
    )

    assert not rendered.endswith(
        "\n\n"
    )


def test_pdf_renderer_is_deterministic():
    renderer = ReportRenderer()

    document = executive_document()

    first = renderer.render(
        document,
        "pdf",
    )

    second = renderer.render(
        document,
        "pdf",
    )

    assert first == second


def test_pdf_wrap_splits_long_unbroken_token():
    renderer = ReportRenderer()

    token = "A" * 1200

    lines = renderer._pdf_wrap(
        token,
        font_name="Helvetica",
        font_size=9,
        max_width=495,
    )

    assert len(lines) > 1

    assert "".join(
        lines
    ) == token

    from reportlab.pdfbase.pdfmetrics import (
        stringWidth,
    )

    assert all(
        stringWidth(
            line,
            "Helvetica",
            9,
        ) <= 495
        for line in lines
    )


def test_pdf_wrap_preserves_winansi_unicode_glyphs():
    renderer = ReportRenderer()

    samples = [
        "SOC Report — EXECUTIVE",
        "• Generated: 2026-10-01",
    ]

    for value in samples:
        lines = renderer._pdf_wrap(
            value,
            font_name="Helvetica",
            font_size=9,
            max_width=495,
        )

        assert " ".join(lines) == value
