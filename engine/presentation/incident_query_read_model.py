from copy import deepcopy


class IncidentQueryReadModel:

    VALID_SEVERITIES = (
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    )

    DEFAULT_LIMIT = 20
    MAX_LIMIT = 100

    def __init__(
        self,
        incident_repository,
    ):
        self.incident_repository = (
            incident_repository
        )

    def get(
        self,
        incident_id,
    ):
        incident = (
            self.incident_repository
            .get(
                incident_id
            )
        )

        return deepcopy(
            incident
        )

    def recent(
        self,
        limit=DEFAULT_LIMIT,
        severity=None,
    ):
        bounded_limit = self._limit(
            limit
        )

        normalized_severity = (
            self._severity(
                severity
            )
        )

        if severity is not None:
            if normalized_severity is None:
                return []

            incidents = (
                self.incident_repository
                .list_recent_by_severity(
                    normalized_severity,
                    limit=bounded_limit,
                )
            )

        else:
            incidents = (
                self.incident_repository
                .list_recent(
                    limit=bounded_limit
                )
            )

        return deepcopy(
            incidents
        )

    @classmethod
    def _severity(
        cls,
        severity,
    ):
        if severity is None:
            return None

        normalized = str(
            severity
        ).strip().upper()

        if normalized not in (
            cls.VALID_SEVERITIES
        ):
            return None

        return normalized

    @classmethod
    def _limit(
        cls,
        limit,
    ):
        try:
            normalized = int(
                limit
            )

        except (
            TypeError,
            ValueError,
        ):
            normalized = (
                cls.DEFAULT_LIMIT
            )

        if normalized <= 0:
            return 0

        return min(
            normalized,
            cls.MAX_LIMIT,
        )
