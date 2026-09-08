def generate_report(self, case_id, incident):

        case = self.cases.get(case_id)

        if not case:
            return None

        report = {
            "case_id": case_id,
            "incident_id": case["incident_id"],
            "status": case["status"],
            "assignee": case["assignee"],
            "created": case["created"]
        }