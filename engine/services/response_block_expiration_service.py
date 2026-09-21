from datetime import (
    datetime,
    timezone,
)


class ResponseBlockExpirationService:

    def __init__(
        self,
        repository,
        now_provider=None,
    ):

        self.repository = repository

        self.now_provider = (
            now_provider
            or self._utc_now
        )

    def _utc_now(self):

        return datetime.now(
            timezone.utc
        )

    def _now(self):

        now = self.now_provider()

        if (
            now.tzinfo is None
            or now.utcoffset() is None
        ):

            raise ValueError(
                "now_provider must return "
                "a timezone-aware datetime"
            )

        return now.astimezone(
            timezone.utc
        )

    def sweep(self):

        now = self._now()

        expired = (
            self.repository.list_expired(
                now
            )
        )

        outcomes = []

        for row in expired:

            target = row.get(
                "target"
            )

            if not target:

                outcomes.append({
                    "target": None,
                    "status": "SKIPPED",
                    "reason": (
                        "Expired row has no target"
                    ),
                })

                continue

            try:

                changed = (
                    self.repository
                    .mark_expired(
                        target,
                        now,
                    )
                )

                if not changed:

                    outcomes.append({
                        "target": target,
                        "status": "SKIPPED",
                        "reason": (
                            "Expiration state "
                            "already changed"
                        ),
                    })

                    continue

                outcomes.append({
                    "target": target,
                    "status": "EXPIRED",
                    "desired_state": "UNBLOCKED",
                })

            except Exception as error:

                outcomes.append({
                    "target": target,
                    "status": "FAILED",
                    "error": str(error),
                })

                continue

        return outcomes
