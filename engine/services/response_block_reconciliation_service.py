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
        safety_policy=None,
        now_provider=None,
    ):

        self.repository = repository
        self.response_engine = response_engine

        self.firewall_backend = (
            firewall_backend
        )

        self.safety_policy = (
            safety_policy
            if safety_policy is not None
            else getattr(
                response_engine,
                "safety_policy",
                None,
            )
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
                            row=row,
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
                            row=row,
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
        row,
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

        result = self._execute_affine(
            row=row,
            action_type="BLOCK_IP",
            target=target,
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
        row,
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

        result = self._execute_affine(
            row=row,
            action_type="UNBLOCK_IP",
            target=target,
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

    def _execute_affine(
        self,
        row,
        action_type,
        target,
    ):

        backend = row.get(
            "backend"
        )

        current_mode = getattr(
            self.response_engine,
            "response_mode",
            (
                "simulate"
                if backend == "memory"
                else "enforce"
            ),
        )

        if (
            action_type
            == "BLOCK_IP"
            and self.safety_policy
            is not None
            and self.safety_policy
            .is_protected(
                target
            )
        ):

            return {
                "type": "BLOCK_IP",
                "target": target,
                "status": "PROTECTED",
                "reason": (
                    "Target is protected by "
                    "response safety policy"
                ),
                "backend": "safety_policy",
                "execution_mode": "PROTECTED",
            }

        if backend == "memory":

            if current_mode == "simulate":

                return (
                    self.response_engine
                    .execute({
                        "type": action_type,
                        "target": target,
                        "status": "PENDING",
                    })
                )

            return (
                self._execute_memory(
                    action_type,
                    target,
                )
            )

        if backend == "windows_firewall":

            if self.firewall_backend is None:

                raise RuntimeError(
                    "Windows firewall backend "
                    "is not configured"
                )

            if current_mode == "enforce":

                engine_backend = getattr(
                    self.response_engine,
                    "firewall_backend",
                    None,
                )

                if (
                    engine_backend
                    is self.firewall_backend
                ):

                    return (
                        self.response_engine
                        .execute({
                            "type": action_type,
                            "target": target,
                            "status": "PENDING",
                        })
                    )

            return (
                self._execute_windows_firewall(
                    action_type,
                    target,
                )
            )

        raise RuntimeError(
            "Unsupported response block "
            f"backend: {backend}"
        )

    def _execute_memory(
        self,
        action_type,
        target,
    ):

        action = {
            "type": action_type,
            "target": target,
        }

        if action_type == "BLOCK_IP":

            if (
                target
                in self.response_engine.blocked_ips
            ):

                action.update({
                    "status": "SKIPPED",
                    "reason": (
                        "IP already simulated "
                        "as blocked"
                    ),
                    "backend": "memory",
                    "execution_mode": "SIMULATED",
                })

                return action

            self.response_engine.blocked_ips.add(
                target
            )

            action.update({
                "status": "SIMULATED",
                "backend": "memory",
                "execution_mode": "SIMULATED",
            })

            return action

        if action_type == "UNBLOCK_IP":

            if (
                target
                not in self.response_engine.blocked_ips
            ):

                action.update({
                    "status": "SKIPPED",
                    "reason": (
                        "IP is not simulated "
                        "as blocked"
                    ),
                    "backend": "memory",
                    "execution_mode": "SIMULATED",
                })

                return action

            self.response_engine.blocked_ips.remove(
                target
            )

            action.update({
                "status": "SIMULATED",
                "backend": "memory",
                "execution_mode": "SIMULATED",
            })

            return action

        raise RuntimeError(
            "Unsupported memory action: "
            f"{action_type}"
        )

    def _execute_windows_firewall(
        self,
        action_type,
        target,
    ):

        if action_type == "BLOCK_IP":

            backend_result = (
                self.firewall_backend.block(
                    target
                )
            )

            expected = {
                "CREATED",
                "EXISTS",
            }

        elif action_type == "UNBLOCK_IP":

            backend_result = (
                self.firewall_backend.unblock(
                    target
                )
            )

            expected = {
                "REMOVED",
                "MISSING",
            }

        else:

            raise RuntimeError(
                "Unsupported firewall action: "
                f"{action_type}"
            )

        if not isinstance(
            backend_result,
            dict,
        ):

            raise RuntimeError(
                "Unexpected firewall "
                "action result"
            )

        backend_status = (
            backend_result.get(
                "status"
            )
        )

        if backend_status not in expected:

            raise RuntimeError(
                "Unexpected firewall "
                f"action status: "
                f"{backend_status}"
            )

        action = {
            "type": action_type,
            "target": target,
            "status": "SUCCESS",
            "backend": "windows_firewall",
            "execution_mode": "ENFORCED",
            "backend_status": (
                backend_status
            ),
        }

        rule_name = (
            backend_result.get(
                "rule_name"
            )
        )

        if rule_name is not None:

            action["rule_name"] = (
                rule_name
            )

        return action

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
