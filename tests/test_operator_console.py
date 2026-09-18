from io import StringIO

from rich.console import Console

from engine.presentation.operator_console import (
    OperatorConsoleRenderer,
)


def make_renderer():
    output = StringIO()

    console = Console(
        file=output,
        force_terminal=False,
        width=100,
    )

    return (
        OperatorConsoleRenderer(
            console=console,
        ),
        output,
    )


def test_renderer_exposes_operator_sections():
    renderer, output = make_renderer()

    snapshot = {
        "summary": {
            "incidents": 2,
            "high_critical": 1,
            "campaigns": 1,
            "max_risk": 91.0,
        },
        "incidents": [
            {
                "id": "INC-001",
                "severity": "CRITICAL",
            },
            {
                "id": "INC-002",
                "severity": "LOW",
            },
        ],
        "campaigns": [],
        "cases": [],
        "recent_events": [
            {
                "id": "EVT-001",
            },
        ],
    }

    renderer.render(
        snapshot
    )

    rendered = output.getvalue()

    assert "SOC LAB" in rendered
    assert "Operator Console" in rendered
    assert "Operational Summary" in rendered
    assert "Incidents" in rendered
    assert "Recent" in rendered
    assert "Events" in rendered

    assert "INC-001" in rendered
    assert "CRITICAL" in rendered
    assert "EVT-001" in rendered


def test_renderer_handles_empty_snapshot():
    renderer, output = make_renderer()

    renderer.render({
        "summary": {},
        "incidents": [],
        "campaigns": [],
        "cases": [],
        "recent_events": [],
    })

    rendered = output.getvalue()

    assert "No active incidents" in rendered
    assert "No recent events" in rendered


def test_summary_uses_safe_defaults():
    renderer, output = make_renderer()

    renderer.render({
        "summary": {},
    })

    rendered = output.getvalue()

    assert "Incidents" in rendered
    assert "High / Critical" in rendered
    assert "Campaigns" in rendered
    assert "Maximum Risk" in rendered


def test_event_id_fallback():
    renderer, output = make_renderer()

    renderer.render({
        "recent_events": [
            {
                "event_id": "EVT-FALLBACK",
            },
        ],
    })

    rendered = output.getvalue()

    assert "EVT-FALLBACK" in rendered
