class ResponseSubscriber:

    def __init__(self, logger):

        self.logger = logger

    # =========================

    def on_response(self, payload):

        incident = payload["incident"]

        self.logger(
            f"[RESPONSE] {incident['id']}"
        )