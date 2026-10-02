from io import StringIO

from rich.console import Console
from rich.panel import Panel

from engine.presentation.monitor_console import (
    MonitorConsoleRenderer,
)


def make_renderer(
    force_terminal=False,
    width=100,
):
    output = StringIO()

    console = Console(
        file=output,
        force_terminal=force_terminal,
        width=width,
    )

    return (
        MonitorConsoleRenderer(
            console=console,
        ),
        output,
    )


def monitor_snapshot():
    return {
        "operator": {
            "summary": {
                "incidents": 4,
                "high_critical": 2,
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
                    "severity": "HIGH",
                },
                {
                    "id": "INC-003",
                    "severity": "MEDIUM",
                },
                {
                    "id": "INC-004",
                    "severity": "LOW",
                },
            ],
            "campaigns": [],
            "cases": [],
            "recent_events": [],
        },
        "runtime": {
            "generated_at": (
                "2026-09-24T12:00:00+00:00"
            ),
            "uptime": "01:01:01",
            "queue_depth": 3,
            "checkpoint_lag": "1.0 KiB",
            "events_read": 120,
            "alerts_generated": 8,
            "tasks_completed": 110,
            "task_attempt_failures": 2,
            "tasks_deduplicated": 4,
            "avg_task_latency": "12.5 ms",
        },
        "health": {
            "status": "HEALTHY",
            "reasons": [],
            "snapshot_age_seconds": 1.0,
        },
        "channels": {
            "local": "READY",
            "email": "DISABLED",
            "telegram": "DISABLED",
            "webhook": "READY",
            "threema": "INERT",
        },
    }


def test_renderer_exposes_monitor_sections():
    renderer, output = make_renderer()

    renderer.render(
        monitor_snapshot()
    )

    rendered = output.getvalue()

    for label in (
        "SOC-LAB // MONITOR CONSOLE",
        "MONITOR / OPERATIONS",
        "SYSTEM",
        "READ-ONLY",
        "RUNTIME",
        "ACTIVITY",
        "SOC SUMMARY",
        "INCIDENT FEED",
    ):
        assert label in rendered


def test_runtime_values_are_visible():
    renderer, output = make_renderer()

    renderer.render(
        monitor_snapshot()
    )

    rendered = output.getvalue()

    for value in (
        "HEALTHY",
        "01:01:01",
        "1.0 KiB",
        "12.5 ms",
        "120",
        "110",
    ):
        assert value in rendered


def test_incident_values_are_visible():
    renderer, output = make_renderer()

    renderer.render(
        monitor_snapshot()
    )

    rendered = output.getvalue()

    for value in (
        "INC-001",
        "CRITICAL",
        "INC-002",
        "HIGH",
        "INC-003",
        "MEDIUM",
        "INC-004",
        "LOW",
    ):
        assert value in rendered


def test_renderer_handles_empty_snapshot():
    renderer, output = make_renderer()

    renderer.render({})

    rendered = output.getvalue()

    assert "UNKNOWN" in rendered
    assert "No incidents" in rendered
    assert "00:00:00" in rendered
    assert "0 B" in rendered
    assert "N/A" in rendered


def test_health_semantic_styles():
    renderer, _ = make_renderer()

    assert (
        renderer._health_text(
            "HEALTHY"
        ).style
        == "bold green"
    )

    assert (
        renderer._health_text(
            "DEGRADED"
        ).style
        == "bold yellow"
    )

    assert (
        renderer._health_text(
            "STALE"
        ).style
        == "bold yellow"
    )

    assert (
        renderer._health_text(
            "UNKNOWN"
        ).style
        == "dim"
    )


def test_severity_semantic_styles():
    renderer, _ = make_renderer()

    assert (
        renderer._severity_text(
            "LOW"
        ).style
        == "green"
    )

    assert (
        renderer._severity_text(
            "MEDIUM"
        ).style
        == "yellow"
    )

    assert (
        renderer._severity_text(
            "HIGH"
        ).style
        == "red"
    )

    assert (
        renderer._severity_text(
            "CRITICAL"
        ).style
        == "bold white on red"
    )


def test_color_is_not_only_signal():
    renderer, output = make_renderer(
        force_terminal=False
    )

    renderer.render(
        monitor_snapshot()
    )

    rendered = output.getvalue()

    for label in (
        "HEALTHY",
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
    ):
        assert label in rendered


def test_renderer_emits_ansi_styles_when_terminal():
    renderer, output = make_renderer(
        force_terminal=True
    )

    renderer.render(
        monitor_snapshot()
    )

    rendered = output.getvalue()

    assert "\x1b[" in rendered
    assert "HEALTHY" in rendered
    assert "CRITICAL" in rendered


def test_unknown_values_remain_visible():
    renderer, output = make_renderer()

    snapshot = monitor_snapshot()

    snapshot["health"][
        "status"
    ] = "unexpected"

    snapshot["operator"][
        "incidents"
    ][0]["severity"] = "custom"

    renderer.render(
        snapshot
    )

    rendered = output.getvalue()

    assert "UNEXPECTED" in rendered
    assert "CUSTOM" in rendered


def test_instrument_builder_returns_panel():
    renderer, _ = make_renderer()

    panel = renderer._instrument_panel(
        title="TEST",
        rows=(
            (
                "VALUE",
                "1",
            ),
        ),
    )

    assert isinstance(
        panel,
        Panel,
    )


def test_compact_layout_survives_narrow_terminal():
    renderer, output = make_renderer(
        width=72
    )

    renderer.render(
        monitor_snapshot()
    )

    rendered = output.getvalue()

    assert (
        "SOC-LAB // MONITOR CONSOLE"
        in rendered
    )

    assert "RUNTIME" in rendered
    assert "ACTIVITY" in rendered
    assert "INCIDENT FEED" in rendered


def test_renderer_exposes_no_write_methods():
    public_methods = {
        name
        for name in dir(
            MonitorConsoleRenderer
        )
        if not name.startswith("_")
    }

    forbidden = {
        "save",
        "write",
        "update",
        "delete",
        "remove",
        "send",
        "execute",
        "block",
        "release",
    }

    assert (
        public_methods
        & forbidden
        == set()
    )


def test_renderer_exposes_channel_panel():
    renderer, output = make_renderer()

    renderer.render(
        monitor_snapshot()
    )

    rendered = output.getvalue()

    assert "CHANNELS" in rendered

    for channel in (
        "LOCAL",
        "EMAIL",
        "TELEGRAM",
        "WEBHOOK",
        "THREEMA",
    ):
        assert channel in rendered


def test_channel_status_values_are_visible():
    renderer, output = make_renderer()

    renderer.render(
        monitor_snapshot()
    )

    rendered = output.getvalue()

    assert "READY" in rendered
    assert "DISABLED" in rendered
    assert "INERT" in rendered


def test_channel_semantic_styles():
    renderer, _ = make_renderer()

    assert (
        renderer._channel_status_text(
            "READY"
        ).style
        == "bold green"
    )

    assert (
        renderer._channel_status_text(
            "INERT"
        ).style
        == "bold yellow"
    )

    assert (
        renderer._channel_status_text(
            "DISABLED"
        ).style
        == "dim"
    )

    assert (
        renderer._channel_status_text(
            "UNKNOWN"
        ).style
        == "dim"
    )


def test_missing_channels_fail_read_only_safe():
    renderer, output = make_renderer()

    snapshot = (
        monitor_snapshot()
    )

    snapshot.pop(
        "channels"
    )

    renderer.render(
        snapshot
    )

    rendered = output.getvalue()

    assert "CHANNELS" in rendered

    assert rendered.count(
        "UNKNOWN"
    ) >= 5


def test_channel_color_is_not_only_signal():
    renderer, output = make_renderer(
        force_terminal=False
    )

    renderer.render(
        monitor_snapshot()
    )

    rendered = output.getvalue()

    for label in (
        "READY",
        "DISABLED",
        "INERT",
    ):
        assert label in rendered

def test_renderer_builds_single_dashboard_renderable():
    renderer, _ = make_renderer()

    dashboard = renderer.build_dashboard(
        monitor_snapshot()
    )

    from rich.console import Group

    assert isinstance(
        dashboard,
        Group,
    )


def test_composed_dashboard_preserves_monitor_sections():
    renderer, output = make_renderer()

    dashboard = renderer.build_dashboard(
        monitor_snapshot()
    )

    renderer.console.print(
        dashboard
    )

    rendered = output.getvalue()

    for label in (
        "SOC-LAB // MONITOR CONSOLE",
        "RUNTIME",
        "SOC SUMMARY",
        "ACTIVITY",
        "INCIDENT FEED",
        "CHANNELS",
    ):
        assert label in rendered


def test_dashboard_can_include_command_output_panel():
    from rich.console import Console

    from engine.presentation.monitor_console import (
        MonitorConsoleRenderer,
    )

    console = Console(
        record=True,
        width=120,
    )

    renderer = MonitorConsoleRenderer(
        console=console,
    )

    dashboard = renderer.build_dashboard(
        {},
        command_output=(
            "{'status': 'HEALTHY', "
            "'reasons': []}"
        ),
    )

    console.print(
        dashboard
    )

    rendered = console.export_text()

    assert "COMMAND OUTPUT" in rendered
    assert "'status': 'HEALTHY'" in rendered
    assert "'reasons': []" in rendered
