import uuid
from datetime import datetime
from engine.cli.console_io import safe_print


class CaseManager:

    DEFAULT_QUERY_LIMIT = 20
    MAX_QUERY_LIMIT = 100

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
    def list_recent(
        self,
        limit=DEFAULT_QUERY_LIMIT,
    ):
        bounded_limit = self._bounded_limit(
            limit
        )

        if bounded_limit == 0:
            return []

        ordered = sorted(
            self.cases.values(),
            key=lambda case: str(
                case.get(
                    "created",
                    ""
                )
            ),
            reverse=True,
        )

        return [
            dict(
                case
            )
            for case in ordered[
                :bounded_limit
            ]
        ]

    @classmethod
    def _bounded_limit(
        cls,
        limit,
    ):
        try:
            normalized = int(
                limit
            )

        except (
            TypeError,
            ValueError,
        ):
            normalized = (
                cls.DEFAULT_QUERY_LIMIT
            )

        if normalized <= 0:
            return 0

        return min(
            normalized,
            cls.MAX_QUERY_LIMIT,
        )

    # -------------------------
    def _log(self, case, event):
        case["timeline"].append({
            "time": self._now(),
            "event": event
        })