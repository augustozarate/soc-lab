import json
from datetime import datetime

AUDIT_FILE = "audit.log"

def audit(event_type, data):

    entry = {
        "time": datetime.utcnow().isoformat(),
        "event_type": event_type,
        "data": data
    }

    with open(AUDIT_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
