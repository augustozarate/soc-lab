from datetime import (
    datetime,
    timezone,
)


class ResponseBlockReconciliationService:

    SIMULATED_ALREADY_BLOCKED_REASON = (
        "IP already simulated as blocked"
    )

    SIMULATED_MISSING_REASON = (
        "IP is not simulated as blocked"
    )

    def __init__(
        self,
        repository,
        response_engine,
        firewall_backend=None,
        now_provider=None,
    ):

        self.repository = repository
        self.response_engine = response_engine

        self.firewall_backend = (
            firewall_backend
        )

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

        rows = (
            self.repository
            .list_reconcilable(
                now
            )
        )

        outcomes = []

        for row in rows:

            target = row.get(
                "target"
            )

            if not target:

                outcomes.append({
                    "target": None,
                    "status": "SKIPPED",
                    "reason": (
                        "Reconcilable row "
                        "has no target"
                    ),
                })

                continue

            try:

                actual_blocked = (
                    self._actual_blocked(
                        row
                    )
                )

                desired_state = row.get(
                    "desired_state"
                )

                if (
                    desired_state
                    == "BLOCKED"
                ):

                    outcome = (
                        self._reconcile_blocked(
                            target=target,
                            actual_blocked=(
                                actual_blocked
                            ),
                            now=now,
                        )
                    )

                elif (
                    desired_state
                    == "UNBLOCKED"
                ):

                    outcome = (
                        self._reconcile_unblocked(
                            target=target,
                            actual_blocked=(
                                actual_blocked
                            ),
                            now=now,
                        )
                    )

                else:

                    error = (
                        "Unsupported desired_state: "
                        f"{desired_state}"
                    )

                    self.repository.mark_failed(
                        target,
                        error,
                        now,
                    )

                    outcome = {
                        "target": target,
                        "status": "FAILED",
                        "error": error,
                    }

            except Exception as error:

                try:

                    self.repository.mark_failed(
                        target,
                        (
                            "Reconciliation failed: "
                            f"{error}"
                        ),
                        now,
                    )

                except Exception:
                    pass

                outcome = {
                    "target": target,
                    "status": "FAILED",
                    "error": str(error),
                }

            outcomes.append(
                outcome
            )

        return outcomes

    def _actual_blocked(
        self,
        row,
    ):

        target = row["target"]

        backend = row.get(
            "backend"
        )

        if backend == "memory":

            return (
                target
                in self.response_engine.blocked_ips
            )

        if backend == "windows_firewall":

            if self.firewall_backend is None:

                raise RuntimeError(
                    "Windows firewall backend "
                    "is not configured"
                )

            result = (
                self.firewall_backend
                .is_blocked(
                    target
                )
            )

            if isinstance(
                result,
                bool,
            ):

                return result

            if not isinstance(
                result,
                dict,
            ):

                raise RuntimeError(
                    "Unexpected firewall "
                    "query result"
                )

            status = result.get(
                "status"
            )

            if status == "EXISTS":
                return True

            if status == "MISSING":
                return False

            raise RuntimeError(
                "Unexpected firewall "
                f"query status: {status}"
            )

        raise RuntimeError(
            "Unsupported response block "
            f"backend: {backend}"
        )

    def _reconcile_blocked(
        self,
        target,
        actual_blocked,
        now,
    ):

        if actual_blocked:

            self.repository.mark_blocked_converged(
                target,
                now,
            )

            return {
                "target": target,
                "status": "CONVERGED",
                "desired_state": "BLOCKED",
                "actual_state": "BLOCKED",
                "action": None,
            }

        result = (
            self.response_engine.execute({
                "type": "BLOCK_IP",
                "target": target,
                "status": "PENDING",
            })
        )

        if self._block_converged(
            result
        ):

            self.repository.mark_blocked_converged(
                target,
                now,
            )

            return {
                "target": target,
                "status": "REPAIRED",
                "desired_state": "BLOCKED",
                "actual_state": "BLOCKED",
                "action": result,
            }

        error = (
            self._action_error(
                "BLOCK_IP",
                result,
            )
        )

        self.repository.mark_failed(
            target,
            error,
            now,
        )

        return {
            "target": target,
            "status": "FAILED",
            "error": error,
            "action": result,
        }

    def _reconcile_unblocked(
        self,
        target,
        actual_blocked,
        now,
    ):

        if not actual_blocked:

            self.repository.mark_released(
                target,
                now,
            )

            return {
                "target": target,
                "status": "CONVERGED",
                "desired_state": "UNBLOCKED",
                "actual_state": "UNBLOCKED",
                "action": None,
            }

        result = (
            self.response_engine.execute({
                "type": "UNBLOCK_IP",
                "target": target,
                "status": "PENDING",
            })
        )

        if self._unblock_converged(
            result
        ):

            self.repository.mark_released(
                target,
                now,
            )

            return {
                "target": target,
                "status": "REPAIRED",
                "desired_state": "UNBLOCKED",
                "actual_state": "UNBLOCKED",
                "action": result,
            }

        error = (
            self._action_error(
                "UNBLOCK_IP",
                result,
            )
        )

        self.repository.mark_failed(
            target,
            error,
            now,
        )

        return {
            "target": target,
            "status": "FAILED",
            "error": error,
            "action": result,
        }

    def _block_converged(
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
            != "BLOCK_IP"
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
                "CREATED",
                "EXISTS",
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
            == self.SIMULATED_ALREADY_BLOCKED_REASON
        ):

            return True

        return False

    def _unblock_converged(
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

    def _action_error(
        self,
        action_type,
        result,
    ):

        if not isinstance(
            result,
            dict,
        ):

            return (
                f"{action_type} returned "
                "non-dict result"
            )

        explicit_error = result.get(
            "error"
        )

        if explicit_error:

            return (
                f"{action_type} failed: "
                f"{explicit_error}"
            )

        return (
            f"{action_type} did not converge: "
            f"status={result.get('status')} "
            "execution_mode="
            f"{result.get('execution_mode')} "
            f"backend={result.get('backend')} "
            "backend_status="
            f"{result.get('backend_status')}"
        )
