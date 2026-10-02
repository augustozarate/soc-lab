from copy import deepcopy


class MonitorConsoleController:

    def __init__(
        self,
        read_model,
        renderer,
        incident_query_read_model=None,
    ):
        self.read_model = read_model
        self.renderer = renderer
        self.incident_query_read_model = (
            incident_query_read_model
        )

    def render(
        self,
        incident_limit=10,
    ):
        snapshot = self.read_model.snapshot(
            incident_limit=incident_limit
        )

        self.renderer.render(
            snapshot
        )

        return None

    def build_dashboard(
        self,
        incident_limit=10,
        command_output=None,
    ):
        snapshot = self.read_model.snapshot(
            incident_limit=incident_limit
        )

        if command_output is None:
            return self.renderer.build_dashboard(
                snapshot
            )

        return self.renderer.build_dashboard(
            snapshot,
            command_output=command_output,
        )

    def query_health(
        self,
    ):
        return deepcopy(
            self.read_model.health()
        )

    def query_channels(
        self,
    ):
        return deepcopy(
            self.read_model.channels()
        )

    def query_metrics(
        self,
    ):
        return deepcopy(
            self.read_model.metrics()
        )

    def query_incident(
        self,
        incident_id,
    ):
        if (
            self.incident_query_read_model
            is None
        ):
            raise RuntimeError(
                "Incident query surface "
                "is unavailable"
            )

        return deepcopy(
            self.incident_query_read_model
            .get(
                incident_id
            )
        )

    def query_incidents(
        self,
        limit=20,
        severity=None,
    ):
        if (
            self.incident_query_read_model
            is None
        ):
            raise RuntimeError(
                "Incident query surface "
                "is unavailable"
            )

        return deepcopy(
            self.incident_query_read_model
            .recent(
                limit=limit,
                severity=severity,
            )
        )
