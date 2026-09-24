from rich.console import Console
from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


class MonitorConsoleRenderer:

    HEALTH_STYLES = {
        "HEALTHY": "bold green",
        "DEGRADED": "bold yellow",
        "STALE": "bold yellow",
        "UNKNOWN": "dim",
    }

    SEVERITY_STYLES = {
        "LOW": "green",
        "MEDIUM": "yellow",
        "HIGH": "red",
        "CRITICAL": "bold white on red",
    }

    CHANNEL_STYLES = {
        "READY": "bold green",
        "INERT": "bold yellow",
        "DISABLED": "dim",
        "UNKNOWN": "dim",
    }

    def __init__(
        self,
        console=None,
    ):
        self.console = (
            console
            if console is not None
            else Console()
        )

    def render(
        self,
        snapshot,
    ):
        operator = snapshot.get(
            "operator",
            {},
        )

        runtime = snapshot.get(
            "runtime",
            {},
        )

        health = snapshot.get(
            "health",
            {},
        )

        channels = snapshot.get(
            "channels",
            {},
        )

        self.console.print(
            self.build_header(
                health
            )
        )

        self.console.print(
            self._panel_pair(
                self.build_runtime(
                    runtime,
                    health,
                ),
                self.build_summary(
                    operator
                ),
            )
        )

        self.console.print(
            self._panel_pair(
                self.build_activity(
                    runtime
                ),
                self.build_incidents(
                    operator
                ),
            )
        )

        self.console.print(
            self.build_channels(
                channels
            )
        )

    def build_header(
        self,
        health,
    ):
        status = self._status(
            health.get(
                "status",
                "UNKNOWN",
            )
        )

        line = Text()

        line.append(
            "SOC-LAB // MONITOR CONSOLE",
            style="bold white",
        )

        line.append(
            "    "
        )

        line.append(
            "SYSTEM ",
            style="cyan",
        )

        line.append_text(
            self._health_text(
                status
            )
        )

        line.append(
            "    MODE ",
            style="cyan",
        )

        line.append(
            "READ-ONLY",
            style="bold white",
        )

        return Panel(
            line,
            title="MONITOR / OPERATIONS",
            title_align="right",
            border_style="cyan",
        )

    def build_runtime(
        self,
        runtime,
        health,
    ):
        status = self._status(
            health.get(
                "status",
                "UNKNOWN",
            )
        )

        rows = (
            (
                "HEALTH",
                self._health_text(
                    status
                ),
            ),
            (
                "UPTIME",
                str(
                    runtime.get(
                        "uptime",
                        "00:00:00",
                    )
                ),
            ),
            (
                "QUEUE",
                str(
                    runtime.get(
                        "queue_depth",
                        0,
                    )
                ),
            ),
            (
                "CHECKPOINT LAG",
                str(
                    runtime.get(
                        "checkpoint_lag",
                        "0 B",
                    )
                ),
            ),
            (
                "TASK LATENCY",
                str(
                    runtime.get(
                        "avg_task_latency",
                        "N/A",
                    )
                ),
            ),
        )

        return self._instrument_panel(
            title="RUNTIME",
            rows=rows,
        )

    def build_activity(
        self,
        runtime,
    ):
        rows = (
            (
                "EVENTS",
                str(
                    runtime.get(
                        "events_read",
                        0,
                    )
                ),
            ),
            (
                "ALERTS",
                str(
                    runtime.get(
                        "alerts_generated",
                        0,
                    )
                ),
            ),
            (
                "TASKS",
                str(
                    runtime.get(
                        "tasks_completed",
                        0,
                    )
                ),
            ),
            (
                "FAILURES",
                str(
                    runtime.get(
                        "task_attempt_failures",
                        0,
                    )
                ),
            ),
            (
                "DEDUPLICATED",
                str(
                    runtime.get(
                        "tasks_deduplicated",
                        0,
                    )
                ),
            ),
        )

        return self._instrument_panel(
            title="ACTIVITY",
            rows=rows,
        )

    def build_summary(
        self,
        operator,
    ):
        summary = operator.get(
            "summary",
            {},
        )

        rows = (
            (
                "INCIDENTS",
                str(
                    summary.get(
                        "incidents",
                        0,
                    )
                ),
            ),
            (
                "HIGH / CRITICAL",
                str(
                    summary.get(
                        "high_critical",
                        0,
                    )
                ),
            ),
            (
                "CAMPAIGNS",
                str(
                    summary.get(
                        "campaigns",
                        0,
                    )
                ),
            ),
            (
                "MAXIMUM RISK",
                str(
                    summary.get(
                        "max_risk",
                        0,
                    )
                ),
            ),
        )

        return self._instrument_panel(
            title="SOC SUMMARY",
            rows=rows,
        )

    def build_incidents(
        self,
        operator,
    ):
        incidents = operator.get(
            "incidents",
            [],
        )

        table = Table(
            show_header=True,
            expand=True,
            box=None,
            padding=(0, 1),
        )

        table.add_column(
            "ID",
            style="cyan",
            no_wrap=True,
        )

        table.add_column(
            "SEVERITY",
            no_wrap=True,
        )

        if not incidents:
            table.add_row(
                "-",
                "No incidents",
            )
        else:
            for incident in incidents:
                severity = self._severity(
                    incident.get(
                        "severity",
                        "UNKNOWN",
                    )
                )

                table.add_row(
                    str(
                        incident.get(
                            "id",
                            "-",
                        )
                    ),
                    self._severity_text(
                        severity
                    ),
                )

        return Panel(
            table,
            title="INCIDENT FEED",
            title_align="left",
            border_style="cyan",
        )

    def build_channels(
        self,
        channels,
    ):
        table = Table.grid(
            expand=True,
            padding=(0, 1),
        )

        table.add_column(
            style="cyan",
            ratio=2,
        )

        table.add_column(
            justify="right",
            ratio=1,
        )

        ordered = (
            "local",
            "email",
            "telegram",
            "webhook",
            "threema",
        )

        for channel in ordered:
            status = self._channel_status(
                channels.get(
                    channel,
                    "UNKNOWN",
                )
            )

            table.add_row(
                channel.upper(),
                self._channel_status_text(
                    status
                ),
            )

        return Panel(
            table,
            title="CHANNELS",
            title_align="left",
            border_style="cyan",
        )

    def _panel_pair(
        self,
        left,
        right,
    ):
        if self.console.size.width < 90:
            return Group(
                left,
                right,
            )

        layout = Table.grid(
            expand=True,
            padding=(0, 1),
        )

        layout.add_column(
            ratio=1,
        )

        layout.add_column(
            ratio=1,
        )

        layout.add_row(
            left,
            right,
        )

        return layout

    def _instrument_panel(
        self,
        title,
        rows,
    ):
        table = Table.grid(
            expand=True,
            padding=(0, 1),
        )

        table.add_column(
            style="cyan",
            ratio=2,
        )

        table.add_column(
            justify="right",
            ratio=1,
        )

        for name, value in rows:
            table.add_row(
                name,
                value,
            )

        return Panel(
            Group(
                table
            ),
            title=title,
            title_align="left",
            border_style="cyan",
        )

    def _health_text(
        self,
        status,
    ):
        return Text(
            status,
            style=self.HEALTH_STYLES.get(
                status,
                "dim",
            ),
        )

    def _severity_text(
        self,
        severity,
    ):
        return Text(
            severity,
            style=self.SEVERITY_STYLES.get(
                severity,
                "white",
            ),
        )

    def _channel_status_text(
        self,
        status,
    ):
        return Text(
            status,
            style=self.CHANNEL_STYLES.get(
                status,
                "dim",
            ),
        )

    @staticmethod
    def _channel_status(
        value,
    ):
        if value is None:
            return "UNKNOWN"

        return str(
            value
        ).strip().upper()

    @staticmethod
    def _status(
        value,
    ):
        if value is None:
            return "UNKNOWN"

        return str(
            value
        ).strip().upper()

    @staticmethod
    def _severity(
        value,
    ):
        if value is None:
            return "UNKNOWN"

        return str(
            value
        ).strip().upper()
