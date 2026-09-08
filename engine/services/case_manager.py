import uuid
from datetime import datetime
from engine.cli.console_io import safe_print


class CaseManager:

    def __init__(self):
        self.cases = {}

    def _now(self):
        return datetime.utcnow().isoformat()

    # -------------------------
    # CREATE CASE
    # -------------------------
    def create_case(self, incident):
        case_id = str(uuid.uuid4())[:8]

        case = {
            "id": case_id,
            "incident_id": incident["id"],
            "created": self._now(),
            "status": "NEW",
            "assignee": None,
            "notes": [],
            "evidence": [],
            "timeline": [],
            "severity": incident.get("severity"),
            "ip": incident.get("ip")
        }

        self.cases[case_id] = case

        safe_print("[CASE CREATED]", case_id)
        return case_id

    # -------------------------
    # ASSIGN ANALYST
    # -------------------------
    def assign(self, case_id, analyst):
        case = self.cases.get(case_id)
        if not case:
            return

        case["assignee"] = analyst
        self._log(case, f"Assigned to {analyst}")

    # -------------------------
    # UPDATE STATUS
    # -------------------------
    def update_status(self, case_id, status):
        case = self.cases.get(case_id)
        if not case:
            return

        case["status"] = status
        self._log(case, f"Status changed → {status}")

    # -------------------------
    # ADD NOTE
    # -------------------------
    def add_note(self, case_id, note):
        case = self.cases.get(case_id)
        if not case:
            return

        entry = {
            "time": self._now(),
            "note": note
        }

        case["notes"].append(entry)
        self._log(case, "Note added")

    # -------------------------
    # ADD EVIDENCE
    # -------------------------
    def add_evidence(self, case_id, evidence):
        case = self.cases.get(case_id)
        if not case:
            return

        entry = {
            "time": self._now(),
            "evidence": evidence
        }

        case["evidence"].append(entry)
        self._log(case, "Evidence added")

    # -------------------------
    # SHOW CASE
    # -------------------------
    def show(self, case_id):
        return self.cases.get(case_id)

    # -------------------------
    def list_cases(self):
        return list(self.cases.values())

    # -------------------------
    def _log(self, case, event):
        case["timeline"].append({
            "time": self._now(),
            "event": event
        })