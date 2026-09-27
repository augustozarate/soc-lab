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
