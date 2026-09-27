from copy import deepcopy


class OperatorConsoleController:

    def __init__(
        self,
        read_model,
        renderer,
    ):
        self.read_model = read_model
        self.renderer = renderer

    def query_cases(
        self,
        limit=20,
    ):
        return deepcopy(
            self.read_model.cases(
                limit=limit
            )
        )

    def query_summary(
        self,
    ):
        return deepcopy(
            self.read_model.summary()
        )

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
