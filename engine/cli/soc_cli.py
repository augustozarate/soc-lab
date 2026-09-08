import json
import difflib
import threading

from engine.telemetry.metrics import metrics
from engine.analysis.attack_view import render_story
from engine.cli.console_io import console_lock
from engine.cli.console_io import safe_print as print
from engine.services.ai_analyst import AIAnalyst
from engine.cli.command_parser import CommandParser
from rich.table import Table
from engine.cli.console_output import log

COMMAND_TREE = {
    "help": {"advanced": {}},

    "incidents": {
        "list": {},
        "show": {},
        "search": {}
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

class SOCConsole:

    def __init__(self, incident_manager, case_manager, simulator=None, event_cache=None, threat_graph=None, campaign_tracker=None, ai_analyst=None):
        self.routes = {
            # BASE COMMANDS
            ("help", None): self.help,
            ("case", None): self.list_cases,        # opcional
            ("ai", None): self.ai_help,             # opcional
            ("util", None): self.util_help,         # opcional
            ("where", None): self.where,

            # SUBCOMMANDS
            ("incidents", None): self.cmd_incidents_list,
            ("incidents", "list"): self.cmd_incidents_list,
            ("incidents", "search"): self.search_incidents,
            ("incidents", "show"): self.show_incident,

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
    
        self.im = incident_manager
        self.cm = case_manager
        self.simulator = simulator
        self.event_cache = event_cache or []
        self.threat_graph = threat_graph
        self.campaign_tracker = campaign_tracker
        self.ai = ai_analyst or AIAnalyst()
        self.parser = CommandParser(COMMAND_TREE)
        self._thread = None

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
                with console_lock:
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
        except Exception as e:
            suggestion = self.suggest_command(cmd.split()[0])
            if suggestion:
                print(f"[ERROR] Unknown command '{cmd}'. Did you mean '{suggestion}'?")
            else:
                print(f"[ERROR] {str(e)}")
    
    def search_incidents(self, args, flags, input_data=None):
        filters = self.parse_filters(args)

        results = []
        for inc in self.im.incidents.values():
            if all(str(inc.get(k)) == v for k, v in filters.items()):
                results.append(inc)

        return results

    def count(self, args, flags, input_data):
        if input_data is None:
            input_data = list(self.im.incidents.values())
        return len(input_data)
    
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
                new_d["intel"] = getattr(self.ai.memory, "memory", {}).get(ip, {})

            enriched.append(new_d)

        return enriched

    def _execute_command(self, cmd):
        pipeline = [c.strip() for c in cmd.split("|")]
        data = None

        for i, stage in enumerate(pipeline):
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

    def list_incidents(self, args=None, flags=None, input_data=None):
        return list(self.im.incidents.values())
    
    def cmd_incidents_list(self, args, flags, data):
        incidents = list(self.im.incidents.values())

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

        inc = self.im.get(incident_id)
        if inc:
            print(json.dumps(inc, indent=2))
        else:
            print("Incident not found")

    # =========================

    def show_timeline(self, incident_id):

        for inc in self.im.incidents.values():
            if inc["id"] == incident_id:

                print("\n=== ATTACK TIMELINE ===")

                for event in inc["timeline"]:
                    print(f"{event['time']} -> {event['event']}")

                return

        print("Incident not found")

    # =========================

    def hunt_ip(self, ip):

        for inc in self.im.incidents.values():
            if inc["ip"] == ip:
                print(f"FOUND INCIDENT {inc['id']} (Severity {inc['severity']})")
                return

        print("No incidents for that IP")

    def pivot_ip(self, ip):

        print(f"\n=== PIVOT: IP {ip} ===\n")

        # Incidents
        print("Incidents:")
        for inc in self.im.incidents.values():
            if inc["ip"] == ip:
                print(f"- {inc['id']} ({inc['severity']})")

        # Cases
        print("\nCases:")
        for cid, case in self.cm.cases.items():
            if case["incident_id"]:
                inc = self.im.get(case["incident_id"])
                if inc and inc["ip"] == ip:
                    print(f"- {cid} ({case['status']})")

        # Events
        print("\nRecent Events:")
        for event in self.event_cache[-10:]:
            if event.get("ip") == ip:
                print(f"- {event.get('message', 'unknown')}")

    def enrich_ip(self, ip):

        print(f"\n=== ENRICHMENT: {ip} ===\n")

        # Threat Intel
        for inc in self.im.incidents.values():
            if inc["ip"] == ip:
                intel = inc.get("alerts", [{}])[0].get("threat_intel", {})
                print(f"Reputation: {intel.get('reputation')}")
                print(f"Confidence: {intel.get('confidence')}")
                break

        # Threat Memory
        print("\nObserved Tactics:")
        # si guardas en threat_memory como dict[ip] = [tactics]
        # ajusta según tu implementación
        # ejemplo:
        # tactics = threat_memory.get(ip)
        # for t in tactics: print(t)

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

        incident = self.im.get(incident_id)

        if not incident:
            # intentar como campaign
            campaign = self.campaign_tracker.campaigns.get(incident_id)
            if campaign:
                print("That is a CAMPAIGN ID. Use: campaign show <id>")
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

    def list_campaigns(self, args=None, flags=None, data=None):

        campaigns = self.campaign_tracker.campaigns

        if not campaigns:
            print("No campaigns yet")
            return

        result = []

        for cid, c in campaigns.items():
            row = {
                "id": cid,
                "ip": c.get("entities", {}).get("ip", ["-"])[0],
                "stage": c.get("stage"),
                "risk": c.get("risk"),
                "incidents": len(c.get("incidents", []))
            }
            result.append(row)

        return result

    def explain_incident(self, incident_id):

        incident = self.im.get(incident_id)

        if not incident:
            # intentar como campaign
            campaign = self.campaign_tracker.campaigns.get(incident_id)
            if campaign:
                print("That is a CAMPAIGN ID. Use: campaign show <id>")
                return

        analysis = incident.get("ai_analysis")

        if not analysis:
            print("No AI analysis available")
            return

        print("\n=== AI ANALYSIS ===\n")

        print(f"IP: {analysis['ip']}")
        print(f"Severity: {analysis['severity']}")
        print(f"Tactic: {analysis['tactic']}")
        print(f"Technique: {analysis['technique']}")

        print("\nSummary:")
        for s in analysis["summary"]:
            print(f"- {s}")

        print("\nRecommended Actions:")
        for a in analysis["recommended_actions"]:
            print(f"- {a}")

        print(f"\nConfidence: {analysis['confidence']}")

    def ask_ai(self, args, flags, data):
        if len(args) < 2:
            print("Usage: ai ask <incident_id> <question>")
            return

        incident_id = args[0]
        question = " ".join(args[1:])

        incident = self.im.get(incident_id)
        if not incident:
            print("Incident not found")
            return

        campaign = None
        if incident.get("campaign_id"):
            campaign = self.campaign_tracker.campaigns.get(incident["campaign_id"])

        response = self.ai.ask(
            incident,
            question,
            self.threat_graph,
            campaign
        )

        print("\n=== AI RESPONSE ===\n")
        print(response)

    def ai_chat(self, incident_id):

        incident = self.im.get(incident_id)

        if not incident:
            # intentar como campaign
            campaign = self.campaign_tracker.campaigns.get(incident_id)
            if campaign:
                print("That is a CAMPAIGN ID. Use: campaign show <id>")
                return

        campaign = None
        if incident.get("campaign_id") and self.campaign_tracker:
            campaign = self.campaign_tracker.campaigns.get(incident["campaign_id"])

        print("\n=== AI CHAT SESSION STARTED ===")
        print("Type 'exit' to leave\n")

        while True:
            try:
                q = input("ai> ").strip()

                if q.lower() in ["exit", "quit"]:
                    print("Exiting AI chat\n")
                    break

                response = self.ai.ask(
                    incident,
                    q,
                    self.threat_graph,
                    campaign
                )

                print(response)

            except KeyboardInterrupt:
                print("\nExiting AI chat\n")
                break

    def ai_help(self, args=None, flags=None, data=None):
        print("AI commands:")
        print("ai ask <incident_id> <question>")

    def util_help(self, args=None, flags=None, data=None):
        print("Util commands:")
        print("util count | sort | where | fields | table | json")

    def load_intel_file(self, path):

        try:
            with open(path) as f:
                data = json.load(f)

            print(f"Loaded {len(data)} threat indicators")

            # opcional: guardar en memory
            for entry in data:
                ip = entry.get("ip")
                if ip:
                    self.ai.memory.update_ip(ip, risk=entry.get("risk", 50))

        except Exception as e:
            print(f"Error loading intel: {e}")

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
        incident = self.im.get(incident_id)

        if not incident:
            # intentar como campaign
            campaign = self.campaign_tracker.campaigns.get(incident_id)
            if campaign:
                print("That is a CAMPAIGN ID. Use: campaign show <id>")
                return

        story = incident.get("attack_story")

        if not story:
            print("No attack story available")
            return

        render_story(story)

    def list_cases(self, args=None, flags=None, data=None):
        if not self.cm.cases:
            print("No cases available")
            return

        for cid, case in self.cm.cases.items():
            print(
                f"{cid} | Incident {case['incident_id']} | "
                f"Status: {case['status']} | Analyst: {case['assignee']}"
            )

    def show_campaign(self, args, flags, data):
        if not args:
            print("Usage: campaign show <id>")
            return

        cid = args[0]
        campaign = self.campaign_tracker.campaigns.get(cid)

        if not campaign:
            print("Campaign not found")
            return

        print("\n=== CAMPAIGN DETAILS ===\n")

        print(f"ID: {campaign['id']}")
        print(f"Stage: {campaign.get('stage')}")
        print(f"Risk: {campaign.get('risk')}")

        ip = campaign.get("entities", {}).get("ip", [])
        if ip:
            print(f"Primary IP: {ip[0]}")

        print("\n--- Incidents ---")
        for iid in campaign.get("incidents", []):
            inc = self.im.get(iid)
            if inc:
                print(f"- {iid} ({inc.get('severity')})")

        print("\n--- MITRE Techniques ---")
        for t in campaign.get("techniques", []):
            print(f"- {t}")

        print("\n--- Timeline ---")
        for t in campaign.get("timeline", []):
            print(f"- {t}")
        print("\n========================\n")

    def show_campaign_graph(self, args, flags, data):
        if not args:
            print("Usage: campaign graph <id>")
            return

        cid = args[0]

        campaign = self.campaign_tracker.campaigns.get(cid)

        if not campaign:
            print("Campaign not found")
            return

        # construir graph dinámico
        from engine.correlación.campaign_graph import CampaignGraph
        graph = CampaignGraph()
        graph.build_from_campaign(campaign, self.im)

        view = graph.get_view(cid)

        print("\n=== CAMPAIGN GRAPH ===\n")

        # NODES
        print("[NODES]")
        for nid, ntype in view["nodes"].items():
            if cid == nid or any(cid in e for e in view["edges"] if nid in e):
                print(f"{ntype}: {nid}")

        # EDGES (SOC STYLE)
        print("\n[RELATIONSHIPS]\n")

        for src, dst, rel in view["edges"]:
            print(f"{src} ──[{rel}]──> {dst}")

        print("\n========================\n")

    def suggest_command(self, cmd):
        commands = [c[0] for c in self.routes.keys()]
        match = difflib.get_close_matches(cmd, commands, n=1)
        return match[0] if match else None
    
    def cmd_graph(self, args, flags, data):
        if not args:
            print("Usage: graph <incident_id>")
            return

        self.show_graph(args[0])