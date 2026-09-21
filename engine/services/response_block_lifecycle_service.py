from datetime import (
    datetime,
    timedelta,
    timezone,
)


class ResponseBlockLifecycleService:

    DUPLICATE_SIMULATION_REASON = (
        "IP already simulated as blocked"
    )

    def __init__(
        self,
        repository,
        ttl_seconds,
        now_provider=None,
    ):

        ttl_seconds = int(
            ttl_seconds
        )

        if ttl_seconds <= 0:

            raise ValueError(
                "ttl_seconds must be "
                "greater than 0"
            )

        self.repository = repository
        self.ttl_seconds = ttl_seconds

        self.now_provider = (
            now_provider
            or self._utc_now
        )

    def _utc_now(self):

        return datetime.now(
            timezone.utc
        )

    def observe(
        self,
        action_result,
        incident,
    ):

        if not self._is_durable_block(
            action_result
        ):

            return None

        target = action_result.get(
            "target"
        )

        if not target:
            return None

        now = self.now_provider()

        if (
            now.tzinfo is None
            or now.utcoffset() is None
        ):

            raise ValueError(
                "now_provider must return "
                "a timezone-aware datetime"
            )

        now = now.astimezone(
            timezone.utc
        )

        expires_at = (
            now
            + timedelta(
                seconds=self.ttl_seconds
            )
        )

        return self.repository.upsert_active(
            target=target,
            expires_at=expires_at,
            execution_mode=(
                action_result.get(
                    "execution_mode"
                )
            ),
            backend=(
                action_result.get(
                    "backend"
                )
            ),
            rule_name=(
                action_result.get(
                    "rule_name"
                )
            ),
            source_incident_id=(
                incident.get("id")
                if incident
                else None
            ),
        )

    def _is_durable_block(
        self,
        action_result,
    ):

        if not isinstance(
            action_result,
            dict,
        ):
            return False

        if (
            action_result.get("type")
            != "BLOCK_IP"
        ):
            return False

        status = action_result.get(
            "status"
        )

        execution_mode = (
            action_result.get(
                "execution_mode"
            )
        )

        backend = action_result.get(
            "backend"
        )

        if (
            status == "SUCCESS"
            and execution_mode == "ENFORCED"
            and backend == "windows_firewall"
            and action_result.get(
                "backend_status"
            ) in {
                "CREATED",
                "EXISTS",
            }
        ):

            return True

        if (
            status == "SIMULATED"
            and execution_mode == "SIMULATED"
            and backend == "memory"
        ):

            return True

        if (
            status == "SKIPPED"
            and execution_mode == "SIMULATED"
            and backend == "memory"
            and action_result.get(
                "reason"
            )
            == self.DUPLICATE_SIMULATION_REASON
        ):

            return True

        return False
