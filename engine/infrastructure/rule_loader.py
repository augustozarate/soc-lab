import os
import yaml
from engine.cli.console_io import safe_print

class RuleLoader:

    def __init__(self, rules_path):
        self.rules_path = rules_path
        self.rules = []

    def load(self):
        self.rules = []

        for file in os.listdir(self.rules_path):

            if not file.endswith(".yml"):
                continue

            full_path = os.path.join(self.rules_path, file)

            with open(full_path, "r", encoding="utf-8") as f:
                rule = yaml.safe_load(f)
                self.rules.append(rule)

        safe_print(f"[RULE ENGINE] Loaded {len(self.rules)} rules")

        return self.rules
