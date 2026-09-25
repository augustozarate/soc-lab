from copy import deepcopy


class MonitorConsoleController:

    def __init__(
        self,
        read_model,
        renderer,
    ):
        self.read_model = read_model
        self.renderer = renderer

    def render(
        self,
        recent_event_limit=10,
    ):
        snapshot = self.read_model.snapshot(
            recent_event_limit=recent_event_limit
        )

        self.renderer.render(
            snapshot
        )

        return snapshot

    def query_health(
        self,
        recent_event_limit=10,
    ):
        snapshot = self.read_model.snapshot(
            recent_event_limit=recent_event_limit
        )

        return deepcopy(
            snapshot.get(
                "health",
                {},
            )
        )

    def query_channels(
        self,
        recent_event_limit=10,
    ):
        snapshot = self.read_model.snapshot(
            recent_event_limit=recent_event_limit
        )

        return deepcopy(
            snapshot.get(
                "channels",
                {},
            )
        )

    def query_metrics(
        self,
        recent_event_limit=10,
    ):
        snapshot = self.read_model.snapshot(
            recent_event_limit=recent_event_limit
        )

        return deepcopy(
            snapshot.get(
                "runtime",
                {},
            )
        )
