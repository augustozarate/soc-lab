import json
import os
from datetime import datetime
from rich.table import Table
from rich.panel import Panel
from engine.cli.console_output import log

ALERT_PATH = "C:/SOC/alerts"

class AlertManager:

    def __init__(self):
        os.makedirs(ALERT_PATH, exist_ok=True)

    def build_alert(self, alert_data, source="RULE"):
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "source": source,
            "alert": alert_data
        }

    def save_alert(self, alert):
        filename = datetime.utcnow().strftime("%Y-%m-%d") + ".log"
        filepath = os.path.join(ALERT_PATH, filename)

        with open(filepath, "a") as f:
            f.write(json.dumps(alert) + "\n")

    def process(self, alert_data, source="RULE"):
        alert = self.build_alert(alert_data, source)
        self.save_alert(alert)

        sev = alert_data.get("severity", "LOW")
        text_color, border_color = self.color_severity(sev)

        def safe(val):
            return str(val) if val is not None else "-"

        alert_type = alert_data.get("rule_id") or alert_data.get("type") or "UNKNOWN"

        table = Table(show_header=False, box=None)
        table.add_row("Time", alert["timestamp"])
        table.add_row("Type", alert_type)
        table.add_row("IP", safe(alert_data.get("ip")))
        table.add_row("Severity", f"[{text_color}]{sev}[/{text_color}]")
        table.add_row("Risk", safe(alert_data.get("risk_score")))

        intel = alert_data.get("threat_intel", {})
        if intel:
            table.add_row("Intel", f"{intel.get('reputation')} ({intel.get('confidence')}%)")

        panel = Panel(
            table,
            title=f"[bold {text_color}]🚨 SOC ALERT[/bold {text_color}]",
            border_style=border_color,
            padding=(1, 2)
        )

        log(panel)

    def safe(val, default="-"):
        return str(val) if val is not None else default

    def color_severity(self, sev):
        return {
            "LOW": ("green", "green"),
            "MEDIUM": ("yellow", "yellow"),
            "HIGH": ("bold red", "red"),
            "CRITICAL": ("bold white on red", "red")
        }.get(sev, ("white", "white"))
