class EntityResolver:

    def extract(self, alert):
        entities = {}

        if "ip" in alert:
            entities["ip"] = alert["ip"]

        if "user" in alert:
            entities["user"] = alert["user"]

        if "host" in alert:
            entities["host"] = alert["host"]

        if "process" in alert:
            entities["process"] = alert["process"]

        return entities