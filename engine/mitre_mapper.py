import yaml
import os
from engine.cli.console_io import safe_print


class MitreMapper:

    def __init__(self, mapping_file):
        self.mapping_file = mapping_file
        self.mappings = self._load()

    def _load(self):
        if not os.path.exists(self.mapping_file):
            safe_print("[MITRE] Mapping file not found")
            return {}

        with open(self.mapping_file, "r") as f:
            data = yaml.safe_load(f) or {}

        safe_print(f"[MITRE] Loaded {len(data)} mappings")
        return data

    def enrich(self, alert):

        alert_type = alert.get("type")

        if not alert_type:
            return alert

        mitre = self.mappings.get(alert_type)

        if mitre:
            alert["mitre"] = {
                "tactic": mitre["tactic"],
                "technique_id": mitre["technique_id"],
                "technique": mitre["technique"]
            }

        return alert