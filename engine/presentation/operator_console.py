from rich.console import Console
from rich.panel import Panel
from rich.table import Table


class OperatorConsoleRenderer:

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
        self.console.print(
            self.build_header()
        )

        self.console.print(
            self.build_summary(
                snapshot.get(
                    "summary",
                    {},
                )
            )
        )

        self.console.print(
            self.build_incidents(
                snapshot.get(
                    "incidents",
                    [],
                )
            )
        )

        self.console.print(
            self.build_recent_events(
                snapshot.get(
                    "recent_events",
                    [],
                )
            )
        )

    def build_header(self):
        return Panel(
            "[bold]SOC LAB[/bold]\n"
            "Operator Console",
            title="SYSTEM",
            border_style="cyan",
        )

    def build_summary(
        self,
        summary,
    ):
        table = Table(
            title="Operational Summary",
            show_header=True,
        )

        table.add_column(
            "Metric"
        )

        table.add_column(
            "Value",
            justify="right",
        )

        rows = (
            (
                "Incidents",
                summary.get(
                    "incidents",
                    0,
                ),
            ),
            (
                "High / Critical",
                summary.get(
                    "high_critical",
                    0,
                ),
            ),
            (
                "Campaigns",
                summary.get(
                    "campaigns",
                    0,
                ),
            ),
            (
                "Maximum Risk",
                summary.get(
                    "max_risk",
                    0,
                ),
            ),
        )

        for name, value in rows:
            table.add_row(
                name,
                str(value),
            )

        return table

    def build_incidents(
        self,
        incidents,
    ):
        table = Table(
            title="Incidents",
            show_header=True,
        )

        table.add_column(
            "ID"
        )

        table.add_column(
            "Severity"
        )

        if not incidents:
            table.add_row(
                "-",
                "No active incidents",
            )

            return table

        for incident in incidents:
            table.add_row(
                str(
                    incident.get(
                        "id",
                        "-",
                    )
                ),
                str(
                    incident.get(
                        "severity",
                        "UNKNOWN",
                    )
                ),
            )

        return table

    def build_recent_events(
        self,
        events,
    ):
        table = Table(
            title="Recent Events",
            show_header=True,
        )

        table.add_column(
            "Event"
        )

        if not events:
            table.add_row(
                "No recent events"
            )

            return table

        for event in events:
            event_id = (
                event.get("id")
                or event.get("event_id")
                or "-"
            )

            table.add_row(
                str(event_id)
            )

        return table
