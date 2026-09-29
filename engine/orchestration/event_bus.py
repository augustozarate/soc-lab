class EventBus:

    def __init__(self):

        self.subscribers = {}

    # =========================

    def subscribe(self, event, handler):

        self.subscribers.setdefault(
            event,
            []
        ).append(handler)

    # =========================

    def emit(self, event, payload=None):

        handlers = self.subscribers.get(
            event,
            []
        )

        for handler in handlers:

            try:
                handler(payload)

            except Exception as e:
                print(
                    f"[EVENT BUS ERROR] {event}: {e}"
                )