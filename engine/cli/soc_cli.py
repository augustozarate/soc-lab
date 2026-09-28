import json
import difflib
import threading

from engine.analysis.attack_view import render_story
from engine.cli.console_io import safe_print as print
from engine.cli.command_parser import (
    CommandParser,
    UnknownCommandError,
)
from rich.table import Table
from engine.cli.console_output import log

COMMAND_TREE = {
    "help": {"advanced": {}},

    "operator": {},
    "monitor": {},
    "health": {},
    "channels": {},
    "metrics": {},

    "report": {
        "render": {},
        "export": {},
    },

    "incidents": {
        "list": {},
        "show": {},
        "search": {},
        "recent": {}
    },

    "case": {
        "create": {},
        "assign": {},
        "list": {}
    },

    "ai": {
        "ask": {}
    },

    "story": {
        "show": {}
    },

    "campaign": {
        "list": {},
        "show": {},
        "graph": {}
    },

    "graph": {
        "incident": {},
        "campaign": {}
    },

    "util": {
        "count": {},
        "fields": {},
        "sort": {},
        "head": {},
        "tail": {},
        "uniq": {},
        "where": {},
        "json": {},
        "table": {},
        "pivot": {},
        "enrich": {}
    },

    "group": {}
}

READ_ONLY_SHORTCUTS = {
    "m": "monitor",
    "h": "health",
    "c": "channels",
    "r": "incidents recent",
    "1": (
        "incidents recent "
        "--severity CRITICAL"
    ),
    "2": (
        "incidents recent "
        "--severity HIGH"
    ),
}


class _CLIIncidentReader:

    def __init__(
        self,
        query,
    ):
        self.query = query

    def get(
        self,
        incident_id,
    ):
        return self.query(
            incident_id
        )


class SOCConsole:

    def __init__(
        self,
        threat_graph=None,
        ai_analyst=None,
        operator_console_controller=None,
        monitor_console_controller=None,
        report_application_service=None,
        campaign_console_controller=None,
    ):
        self.routes = {
            # BASE COMMANDS
            ("help", None): self.help,
            ("operator", None): self.show_operator_console,
            ("monitor", None): self.show_monitor_console,
            ("health", None): self.show_monitor_health,
            ("channels", None): self.show_monitor_channels,
            ("metrics", None): self.show_monitor_metrics,

            # REPORTING
            ("report", "render"): self.render_report,
            ("report", "export"): self.export_report,

            ("case", None): self.list_cases,        # opcional
            ("ai", None): self.ai_help,             # opcional
            ("util", None): self.util_help,         # opcional
            ("where", None): self.where,

            # SUBCOMMANDS
            ("incidents", None): self.cmd_incidents_list,
            ("incidents", "list"): self.cmd_incidents_list,
            ("incidents", "search"): self.search_incidents,
            ("incidents", "show"): self.show_incident,
            ("incidents", "recent"): self.show_recent_incidents,

            # CAMPAIGNS
            ("campaign", None): self.list_campaigns,
            ("campaign", "list"): self.list_campaigns,
            ("campaign", "show"): self.show_campaign,
            ("campaign", "graph"): self.show_campaign_graph,

            ("campaigns", None): self.list_campaigns,
            ("campaigns", "list"): self.list_campaigns,
            ("campaigns", "show"): self.show_campaign,
            ("campaigns", "graph"): self.show_campaign_graph,

            ("util", "count"): self.count,
            ("util", "fields"): self.fields,
            ("util", "sort"): self.sort,
            ("util", "head"): self.head,
            ("util", "tail"): self.tail,
            ("util", "uniq"): self.uniq,
            ("util", "where"): self.where,
            ("util", "json"): self.to_json,
            ("util", "table"): self.table,
            ("util", "pivot"): self.pivot,
            ("util", "enrich"): self.enrich,

            # AI
            ("ai", "ask"): self.ask_ai,

            # STORY (dejar SOLO esta)
            ("story", "show"): self.cmd_story,

            # GRAPH
            ("graph", None): self.cmd_graph,
            ("graph", "incident"): self.cmd_graph,
            ("graph", "campaign"): self.show_campaign_graph,

            ("help", "advanced"): self.help_advanced,

            ("group", None): self.group,
        }

        self.threat_graph = threat_graph
        self.ai = ai_analyst
        self.operator_console_controller = (
            operator_console_controller
        )
        self.monitor_console_controller = (
            monitor_console_controller
        )
        self.report_application_service = (
            report_application_service
        )
        self.campaign_console_controller = (
            campaign_console_controller
        )
        self.parser = CommandParser(COMMAND_TREE)
        self._thread = None

    @staticmethod
    def _report_type(
        args,
    ):
        if not args:
            raise ValueError(
                "Usage: report <render|export> "
                "<executive|technical|advanced>"
            )

        value = str(
            args[0]
        ).strip().lower()

        if value not in {
            "executive",
            "technical",
            "advanced",
        }:
            raise ValueError(
                "Unsupported report type"
            )

        return value

    @staticmethod
    def _report_format(
        flags,
    ):
        flags = flags or {}

        value = str(
            flags.get(
                "format",
                "markdown",
            )
        ).strip().lower()

        if value not in {
            "json",
            "markdown",
            "pdf",
        }:
            raise ValueError(
                "Unsupported report format"
            )

        return value

    @staticmethod
    def _report_limit(
        flags,
        name,
    ):
        flags = flags or {}

        value = flags.get(
            name
        )

        if value is None:
            return None

        try:
            normalized = int(
                value
            )

        except (
            TypeError,
            ValueError,
        ) as exc:
            raise ValueError(
                f"Invalid report {name} limit"
            ) from exc

        if normalized < 0:
            raise ValueError(
                f"Invalid report {name} limit"
            )

        return normalized

    @staticmethod
    def _report_period(
        flags,
    ):
        flags = flags or {}

        label = flags.get(
            "period"
        )

        if label is None:
            return None

        normalized = str(
            label
        ).strip()

        if not normalized:
            raise ValueError(
                "Invalid report period"
            )

        return {
            "label": normalized,
        }

    def _report_kwargs(
        self,
        flags,
    ):
        return {
            "period": self._report_period(
                flags
            ),
            "incident_limit": self._report_limit(
                flags,
                "incidents",
            ),
            "campaign_limit": self._report_limit(
                flags,
                "campaigns",
            ),
            "case_limit": self._report_limit(
                flags,
                "cases",
            ),
        }

    def _require_report_service(
        self,
    ):
        if (
            self.report_application_service
            is None
        ):
            raise RuntimeError(
                "Reporting is unavailable"
            )

        return (
            self.report_application_service
        )

    def render_report(
        self,
        args=None,
        flags=None,
        input_data=None,
    ):
        if input_data is not None:
            raise ValueError(
                "Report commands cannot "
                "consume pipeline input"
            )

        report_type = (
            self._report_type(
                args or []
            )
        )

        output_format = (
            self._report_format(
                flags
            )
        )

        if output_format == "pdf":
            raise ValueError(
                "PDF reports must be exported"
            )

        service = (
            self._require_report_service()
        )

        return service.render(
            report_type=report_type,
            output_format=output_format,
            **self._report_kwargs(
                flags
            ),
        )

    def export_report(
        self,
        args=None,
        flags=None,
        input_data=None,
    ):
        if input_data is not None:
            raise ValueError(
                "Report commands cannot "
                "consume pipeline input"
            )

        args = args or []

        report_type = (
            self._report_type(
                args
            )
        )

        if len(args) < 2:
            raise ValueError(
                "Usage: report export "
                "<executive|technical|advanced> "
                "<filename>"
            )

        basename = str(
            args[1]
        ).strip()

        if not basename:
            raise ValueError(
                "Report filename is required"
            )

        output_format = (
            self._report_format(
                flags
            )
        )

        service = (
            self._require_report_service()
        )

        destination = service.export(
            report_type=report_type,
            output_format=output_format,
            basename=basename,
            **self._report_kwargs(
                flags
            ),
        )

        return (
            "Report exported: "
            f"{destination}"
        )

    def _query_campaign_for_cli(
        self,
        campaign_id,
    ):
        if (
            self.campaign_console_controller
            is None
        ):
            raise RuntimeError(
                "Campaign queries are unavailable"
            )

        return (
            self.campaign_console_controller
            .query_campaign(
                campaign_id
            )
        )

    def _query_campaigns_for_cli(
        self,
        limit=20,
    ):
        if (
            self.campaign_console_controller
            is None
        ):
            raise RuntimeError(
                "Campaign queries are unavailable"
            )

        return (
            self.campaign_console_controller
            .query_campaigns(
                limit=limit
            )
        )


    def show_operator_console(
        self,
        args=None,
        flags=None,
        input_data=None,
    ):
        if self.operator_console_controller is None:
            raise RuntimeError(
                "Operator Console is unavailable"
            )

        return (
            self.operator_console_controller
            .render()
        )

    def show_monitor_console(
        self,
        args=None,
        flags=None,
        input_data=None,
    ):
        if self.monitor_console_controller is None:
            raise RuntimeError(
                "Monitor Console is unavailable"
            )

        return (
            self.monitor_console_controller
            .render()
        )

    def show_monitor_health(
        self,
        args=None,
        flags=None,
        input_data=None,
    ):
        if self.monitor_console_controller is None:
            raise RuntimeError(
                "Monitor Console is unavailable"
            )

        return (
            self.monitor_console_controller
            .query_health()
        )

    def show_monitor_channels(
        self,
        args=None,
        flags=None,
        input_data=None,
    ):
        if self.monitor_console_controller is None:
            raise RuntimeError(
                "Monitor Console is unavailable"
            )

        return (
            self.monitor_console_controller
            .query_channels()
        )

    def show_monitor_metrics(
        self,
        args=None,
        flags=None,
        input_data=None,
    ):
        if self.monitor_console_controller is None:
            raise RuntimeError(
                "Monitor Console is unavailable"
            )

        return (
            self.monitor_console_controller
            .query_metrics()
        )

    # =========================
    # COMMAND LOOP
    # =========================
    def start(self):

        print("\n=== SOC ANALYST CONSOLE ===")
        print("Type 'help' for commands\n")

        import readline

        COMMANDS = self.build_commands(COMMAND_TREE)

        def completer(text, state):
            buffer = readline.get_line_buffer()
            options = [cmd for cmd in COMMANDS if cmd.startswith(buffer)]
            return options[state] if state < len(options) else None

        readline.parse_and_bind("tab: complete")
        readline.set_completer(completer)

        while True:
            try:
                cmd = input("soc> ").strip()

                if not cmd:
                    continue

                self.handle_command(cmd)

            except KeyboardInterrupt:
                print("\n^C (cancelled)")
                continue

            except EOFError:
                print("\nExiting SOC console")
                break

    # =========================
    # ASYNC LIFECYCLE
    # =========================

    def start_async(self):

        if (
            self._thread
            and self._thread.is_alive()
        ):
            return

        self._thread = threading.Thread(
            target=self.start,
            daemon=True,
            name="soc-console"
        )

        self._thread.start()


    def is_alive(self):

        return bool(
            self._thread
            and self._thread.is_alive()
        )

    # =========================

    @staticmethod
    def build_commands(tree, prefix=""):
        cmds = []
        for k, v in tree.items():
            full = f"{prefix} {k}".strip()
            cmds.append(full)
            if isinstance(v, dict):
                cmds.extend(SOCConsole.build_commands(v, full))
        return cmds

    def handle_command(self, cmd):
        try:
            self._execute_command(cmd)

        except UnknownCommandError as exc:
            unknown = str(
                exc
            )

            suggestion = self.suggest_command(
                unknown
            )

            if suggestion:
                print(
                    f"[ERROR] Unknown command "
                    f"'{unknown}'. Did you mean "
                    f"'{suggestion}'?"
                )
            else:
                print(
                    f"[ERROR] Unknown command "
                    f"'{unknown}'."
                )

        except Exception:
            print(
                "[ERROR] Command execution failed"
            )

    @staticmethod
    def parse_filters(args):
        filters = {}

        for expression in args or []:
            if "=" not in expression:
                continue

            key, value = expression.split(
                "=",
                1,
            )

            key = key.strip()

            if not key:
                continue

            filters[key] = value

        return filters

    def search_incidents(self, args, flags, input_data=None):
        filters = self.parse_filters(args)

        incidents = (
            self._query_incidents_for_cli()
            if input_data is None
            else input_data
        )

        return [
            incident
            for incident in incidents or []
            if all(
                str(
                    incident.get(key)
                )
                == value
                for key, value
                in filters.items()
            )
        ]

    def count(self, args, flags, input_data):
        if input_data is not None:
            return len(
                input_data
            )

        summary = (
            self._query_operator_summary()
        )

        try:
            return int(
                summary.get(
                    "incidents",
                    0,
                )
            )

        except (
            TypeError,
            ValueError,
        ):
            return 0

    def fields(self, args, flags, data):
        if not args:
            return data

        return [{k: d.get(k) for k in args} for d in data or []]

    def sort(self, args, flags, data):
        if not self.require_args(args, 1, "util sort <field>"):
            return data

        key = args[0]
        return sorted(data or [], key=lambda x: x.get(key))

    def head(self, args, flags, data):
        n = int(args[0]) if args else 5
        return (data or [])[:n]

    def tail(self, args, flags, data):
        n = int(args[0]) if args else 5
        return (data or [])[-n:]

    def uniq(self, args, flags, data):
        if not args:
            return data

        key = args[0]
        seen = set()
        result = []

        for d in data or []:
            val = d.get(key)
            if val not in seen:
                seen.add(val)
                result.append(d)

        return result

    def where(self, args, flags, data):
        result = []

        for d in data or []:
            match = True

            for expr in args:
                if ">" in expr:
                    k, v = expr.split(">")
                    if float(d.get(k, 0)) <= float(v):
                        match = False
                elif "<" in expr:
                    k, v = expr.split("<")
                    if float(d.get(k, 0)) >= float(v):
                        match = False
                elif "=" in expr:
                    k, v = expr.split("=")
                    if str(d.get(k)) != v:
                        match = False

            if match:
                result.append(d)

        return result

    def to_json(self, args, flags, data):
        print(json.dumps(data, indent=2))
        return data

    def table(self, args, flags, data):
        if not data:
            return data

        keys = args or data[0].keys()

        for row in data:
            print(" | ".join(str(row.get(k, "")) for k in keys))

        return data

    def pivot(self, args, flags, data):
        key = args[0]

        return [d.get(key) for d in data or [] if d.get(key)]

    def enrich(self, args, flags, data):
        enriched = []

        for d in data or []:
            new_d = dict(d)
            ip = new_d.get("ip")

            if ip:
                new_d["intel"] = (
                    self.ai.memory.get_ip_context(
                        ip
                    )
                )

            enriched.append(new_d)

        return enriched

    @staticmethod
    def expand_read_only_shortcut(
        raw,
    ):
        normalized = str(
            raw
        ).strip()

        return READ_ONLY_SHORTCUTS.get(
            normalized,
            normalized,
        )

    def _execute_command(self, cmd):
        pipeline = [c.strip() for c in cmd.split("|")]
        data = None

        for i, stage in enumerate(pipeline):

            if i == 0:
                stage = (
                    self.expand_read_only_shortcut(
                        stage
                    )
                )

            parsed = self.parser.parse(stage)

            if not parsed:
                return

            result = self.dispatch_with_input(parsed, data)

            if result is not None:
                data = result

        # imprimir solo al final
        if isinstance(data, list) and data and isinstance(data[0], dict):
            self.table([], {}, data)
        elif data is not None:
            print(data)

    def dispatch_with_input(self, parsed, input_data):
        key = (parsed["command"], parsed["subcommand"])

        # intento exacto
        if key in self.routes:
            return self.routes[key](parsed["args"], parsed["flags"], input_data)

        # fallback sin subcomando
        fallback_key = (parsed["command"], None)
        if fallback_key in self.routes:
            return self.routes[fallback_key](parsed["args"], parsed["flags"], input_data)

        raise ValueError("Command not implemented")

    def group(self, args, flags, data):
        key = args[0]
        result = {}

        for d in data or []:
            val = d.get(key)
            result.setdefault(val, []).append(d)

        return result

    # =========================

    def help(self, args=None, flags=None, data=None):
        print("""
    === SOC COMMANDS ===

    📌 CORE
    help
    help advanced

    📌 INCIDENTS
    incidents list
    incidents show <id>
    incidents recent
    incidents recent --limit <n>
    incidents recent --severity <level>

    📌 READ-ONLY SHORTCUTS
    m  monitor
    h  health
    c  channels
    r  incidents recent
    1  critical incidents
    2  high incidents

    📌 FILTERING / PIPELINE
    incidents list | util where severity=HIGH
    incidents list | util where risk_score>80
    incidents list | util sort risk_score | util head 3

    📌 DATA OPS
    util count
    util fields <field1> <field2>
    util sort <field>
    util uniq <field>
    util pivot <field>

    📌 OUTPUT
    util table
    util json

    📌 REPORTING
    report render <executive|technical|advanced>
    report render <type> --format json
    report export <type> <filename>
    report export <type> <filename> --format json
    report export <type> <filename> --format pdf
    report ... --period <label>
    report ... --incidents <n> --campaigns <n> --cases <n>

    📌 GROUPING
    group <field>

    📌 AI
    ai ask <incident_id> <question>

    📌 ATTACK VISUALIZATION
    story show <incident_id>
    graph <incident_id>

    📌 CAMPAIGNS
    campaign list
    campaign show <id>
    campaign graph <id>
    """)

    def help_advanced(self, args=None, flags=None, data=None):
        print("""
    === ADVANCED COMMANDS ===

    util uniq <field>
    util pivot <field>
    util tail <n>
    util json
    util table

    ai ask <incident_id> <question>

    story show <incident_id>

    campaign graph <id>
    """)

    # =========================

    def _query_incident_for_cli(
        self,
        incident_id,
    ):
        if self.monitor_console_controller is None:
            raise RuntimeError(
                "Monitor Console is unavailable"
            )

        return (
            self.monitor_console_controller
            .query_incident(
                incident_id
            )
        )

    def _query_incidents_for_cli(
        self,
        limit=100,
    ):
        if self.monitor_console_controller is None:
            raise RuntimeError(
                "Monitor Console is unavailable"
            )

        return (
            self.monitor_console_controller
            .query_incidents(
                limit=limit,
                severity=None,
            )
        )

    def _query_operator_cases(
        self,
        limit=100,
    ):
        if self.operator_console_controller is None:
            raise RuntimeError(
                "Operator Console is unavailable"
            )

        return (
            self.operator_console_controller
            .query_cases(
                limit=limit
            )
        )

    def _query_operator_summary(
        self,
    ):
        if self.operator_console_controller is None:
            raise RuntimeError(
                "Operator Console is unavailable"
            )

        return (
            self.operator_console_controller
            .query_summary()
        )

    def list_incidents(self, args=None, flags=None, input_data=None):
        return self._query_incidents_for_cli()

    def show_recent_incidents(
        self,
        args=None,
        flags=None,
        input_data=None,
    ):
        if self.monitor_console_controller is None:
            raise RuntimeError(
                "Monitor Console is unavailable"
            )

        flags = flags or {}

        limit = flags.get(
            "limit",
            20,
        )

        severity = flags.get(
            "severity"
        )

        return (
            self.monitor_console_controller
            .query_incidents(
                limit=limit,
                severity=severity,
            )
        )

    def cmd_incidents_list(self, args, flags, data):
        incidents = (
            self._query_incidents_for_cli()
        )

        if data is None:  # solo si es comando standalone
            table = Table(title="Incidents")

            table.add_column("ID")
            table.add_column("IP")
            table.add_column("Severity")
            table.add_column("Risk")

            for inc in incidents:
                sev = inc.get("severity", "LOW")
                color = {
                    "LOW": "green",
                    "MEDIUM": "yellow",
                    "HIGH": "red",
                    "CRITICAL": "bold white on red"
                }.get(sev, "white")

                table.add_row(
                    inc["id"],
                    inc.get("ip", "-"),
                    f"[{color}]{sev}[/{color}]",
                    str(inc.get("risk_score", 0))
                )

            log(table)

        return incidents

    # =========================

    def show_incident(self, args, flags, data):
        if not args:
            print("Usage: incidents show <id>")
            return

        incident_id = args[0]

        inc = self._query_incident_for_cli(incident_id)
        if inc:
            print(json.dumps(inc, indent=2))
        else:
            print("Incident not found")

    # =========================

    # =========================

    def print_case_report(self, report):

        print("\n=== CASE REPORT ===\n")

        print(f"Case ID: {report['case_id']}")
        print(f"Incident: {report['incident_id']}")
        print(f"Status: {report['status']}")
        print(f"Assignee: {report['assignee']}")
        print(f"Created: {report['created']}")

        print("\n--- Summary ---")
        print(report["summary"])

        print("\n--- MITRE ---")
        print(report["mitre"])

        print("\n--- Timeline ---")
        for t in report["timeline"]:
            print(f"- {t}")

        print("\n--- Actions ---")
        if report["actions"]:
            for a in report["actions"]:
                print(f"- {a}")
        else:
            print("No actions taken")

        print("\n--- Analyst Notes ---")
        if report["notes"]:
            for n in report["notes"]:
                print(f"- {n}")
        else:
            print("No notes added")

        print("\n====================\n")

    def safe_split(self, cmd, expected):
        parts = cmd.split()
        if len(parts) < expected:
            return None
        return parts

    def show_graph(self, incident_id):

        if not self.threat_graph:
            print("Threat graph not available")
            return

        incident = self._query_incident_for_cli(incident_id)

        if not incident:
            # intentar como campaign
            campaign = (
                self._query_campaign_for_cli(incident_id)
            )

            if campaign:
                print(
                    "That is a CAMPAIGN ID. "
                    "Use: campaign show <id>"
                )
                return

        ctx = self.threat_graph.get_incident_context(incident_id)

        print(f"\n=== THREAT GRAPH: {incident_id} ===\n")

        for ip in ctx["ips"]:
            print(f"IP: {ip}")
            print(f"  └── INCIDENT: {incident_id}")

        for camp in ctx["campaigns"]:
            print(f"        ├── CAMPAIGN: {camp}")

        for mitre in ctx["mitre"]:
            print(f"        └── MITRE: {mitre}")

    def list_campaigns(
        self,
        args=None,
        flags=None,
        data=None,
    ):
        if data is not None:
            raise ValueError(
                "Campaign commands cannot "
                "consume pipeline input"
            )

        return self._query_campaigns_for_cli()


    def ask_ai(self, args, flags, data):
        if len(args) < 2:
            print("Usage: ai ask <incident_id> <question>")
            return

        incident_id = args[0]
        question = " ".join(args[1:])

        incident = self._query_incident_for_cli(incident_id)
        if not incident:
            print("Incident not found")
            return

        campaign = None
        if incident.get("campaign_id"):
            campaign = (
                self._query_campaign_for_cli(incident[
                        "campaign_id"
                    ])
            )

        response = self.ai.ask(
            incident,
            question,
            self.threat_graph,
            campaign
        )

        print("\n=== AI RESPONSE ===\n")
        print(response)


    def ai_help(self, args=None, flags=None, data=None):
        print("AI commands:")
        print("ai ask <incident_id> <question>")

    def util_help(self, args=None, flags=None, data=None):
        print("Util commands:")
        print("util count | sort | where | fields | table | json")

    def suggest(self, token, options):
        return [o for o in options if o.startswith(token)]

    def get_arg(self, parts, index, usage):
        try:
            return parts[index]
        except IndexError:
            print(f"Usage: {usage}")
            return None

    def require_args(self, args, n, usage):
        if len(args) < n:
            print(f"Usage: {usage}")
            return False
        return True

    def cmd_story(self, args, flags, data):
        if not args:
            print("Usage: story <incident_id>")
            return

        incident_id = args[0]
        incident = self._query_incident_for_cli(incident_id)

        if not incident:
            # intentar como campaign
            campaign = (
                self._query_campaign_for_cli(incident_id)
            )

            if campaign:
                print(
                    "That is a CAMPAIGN ID. "
                    "Use: campaign show <id>"
                )
                return

        story = incident.get("attack_story")

        if not story:
            print("No attack story available")
            return

        render_story(story)

    def list_cases(self, args=None, flags=None, data=None):
        cases = (
            self._query_operator_cases()
        )

        if not cases:
            print("No cases available")
            return

        for case in cases:
            cid = case.get(
                "id",
                "-",
            )

            print(
                f"{cid} | Incident "
                f"{case.get('incident_id', '-')} | "
                f"Status: {case.get('status', '-')} | "
                f"Analyst: {case.get('assignee', '-')}"
            )

        return cases

    def show_campaign(
        self,
        args,
        flags,
        data,
    ):
        if data is not None:
            raise ValueError(
                "Campaign commands cannot "
                "consume pipeline input"
            )

        if not args:
            print(
                "Usage: campaign show <id>"
            )
            return

        cid = args[0]
        campaign = self._query_campaign_for_cli(
            cid
        )

        if not campaign:
            print(
                "Campaign not found"
            )
            return

        print(
            "\n=== CAMPAIGN DETAILS ===\n"
        )

        print(
            f"ID: {campaign['id']}"
        )
        print(
            f"Stage: {campaign.get('stage')}"
        )
        print(
            f"Risk: {campaign.get('risk')}"
        )

        ips = (
            campaign.get(
                "entities",
                {},
            ).get(
                "ip",
                [],
            )
        )

        if ips:
            print(
                f"Primary IP: {ips[0]}"
            )

        print(
            "\n--- Incidents ---"
        )

        for iid in campaign.get(
            "incidents",
            [],
        ):
            inc = self._query_incident_for_cli(
                iid
            )

            if inc:
                print(
                    f"- {iid} "
                    f"({inc.get('severity')})"
                )

        print(
            "\n--- MITRE Techniques ---"
        )

        for tactic in campaign.get(
            "tactics",
            [],
        ):
            print(
                f"- {tactic}"
            )

        print(
            "\n--- Timeline ---"
        )

        for item in campaign.get(
            "timeline",
            [],
        ):
            print(
                f"- {item}"
            )

        print(
            "\n========================\n"
        )

    def show_campaign_graph(
        self,
        args,
        flags,
        data,
    ):
        if data is not None:
            raise ValueError(
                "Campaign commands cannot "
                "consume pipeline input"
            )

        if not args:
            print(
                "Usage: campaign graph <id>"
            )
            return

        cid = args[0]
        campaign = self._query_campaign_for_cli(
            cid
        )

        if not campaign:
            print(
                "Campaign not found"
            )
            return

        from engine.correlation.campaign_graph import (
            CampaignGraph,
        )

        graph = CampaignGraph()

        incident_reader = (
            _CLIIncidentReader(
                self._query_incident_for_cli
            )
        )

        graph.build_from_campaign(
            campaign,
            incident_reader,
        )

        view = graph.get_view(
            cid
        )

        print(
            "\n=== CAMPAIGN GRAPH ===\n"
        )

        print(
            "[NODES]"
        )

        for nid, ntype in (
            view["nodes"].items()
        ):
            if (
                cid == nid
                or any(
                    cid in edge
                    for edge
                    in view["edges"]
                    if nid in edge
                )
            ):
                print(
                    f"{ntype}: {nid}"
                )

        print(
            "\n[RELATIONSHIPS]\n"
        )

        for src, dst, rel in (
            view["edges"]
        ):
            print(
                f"{src} ──[{rel}]──> {dst}"
            )

        print(
            "\n========================\n"
        )

    def suggest_command(self, cmd):
        commands = [c[0] for c in self.routes.keys()]
        match = difflib.get_close_matches(cmd, commands, n=1)
        return match[0] if match else None

    def cmd_graph(self, args, flags, data):
        if not args:
            print("Usage: graph <incident_id>")
            return

        self.show_graph(args[0])
