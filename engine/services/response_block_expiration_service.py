from datetime import (
    datetime,
    timezone,
)


class ResponseBlockExpirationService:

    SIMULATED_MISSING_REASON = (
        "IP is not simulated as blocked"
    )

    def __init__(
        self,
        repository,
        response_engine,
        now_provider=None,
    ):

        self.repository = repository
        self.response_engine = response_engine

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

                try:

                    result = (
                        self.response_engine
                        .execute({
                            "type": "UNBLOCK_IP",
                            "target": target,
                            "status": "PENDING",
                        })
                    )

                except Exception as error:

                    self.repository.mark_failed(
                        target,
                        (
                            "UNBLOCK_IP execution "
                            f"failed: {error}"
                        ),
                        now,
                    )

                    outcomes.append({
                        "target": target,
                        "status": "FAILED",
                        "error": str(error),
                    })

                    continue

                if self._is_converged(
                    result
                ):

                    self.repository.mark_released(
                        target,
                        now,
                    )

                    outcomes.append({
                        "target": target,
                        "status": "RELEASED",
                        "action": result,
                    })

                    continue

                error = (
                    self._non_convergent_error(
                        result
                    )
                )

                self.repository.mark_failed(
                    target,
                    error,
                    now,
                )

                outcomes.append({
                    "target": target,
                    "status": "FAILED",
                    "error": error,
                    "action": result,
                })

            except Exception as error:

                outcomes.append({
                    "target": target,
                    "status": "FAILED",
                    "error": str(error),
                })

                continue

        return outcomes

    def _is_converged(
        self,
        result,
    ):

        if not isinstance(
            result,
            dict,
        ):
            return False

        if (
            result.get("type")
            != "UNBLOCK_IP"
        ):
            return False

        if (
            result.get("status")
            == "SUCCESS"
            and result.get(
                "execution_mode"
            )
            == "ENFORCED"
            and result.get("backend")
            == "windows_firewall"
            and result.get(
                "backend_status"
            )
            in {
                "REMOVED",
                "MISSING",
            }
        ):

            return True

        if (
            result.get("status")
            == "SIMULATED"
            and result.get(
                "execution_mode"
            )
            == "SIMULATED"
            and result.get("backend")
            == "memory"
        ):

            return True

        if (
            result.get("status")
            == "SKIPPED"
            and result.get(
                "execution_mode"
            )
            == "SIMULATED"
            and result.get("backend")
            == "memory"
            and result.get("reason")
            == self.SIMULATED_MISSING_REASON
        ):

            return True

        return False

    def _non_convergent_error(
        self,
        result,
    ):

        if not isinstance(
            result,
            dict,
        ):

            return (
                "UNBLOCK_IP returned "
                "non-dict result"
            )

        return (
            "UNBLOCK_IP did not converge: "
            f"status={result.get('status')} "
            "execution_mode="
            f"{result.get('execution_mode')} "
            f"backend={result.get('backend')} "
            "backend_status="
            f"{result.get('backend_status')}"
        )
