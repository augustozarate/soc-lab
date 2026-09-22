class NotificationService:

    def __init__(
        self,
        adapters=None,
        delivery_repository=None,
    ):

        self.adapters = dict(
            adapters or {}
        )

        self.delivery_repository = (
            delivery_repository
        )

    # =========================================
    # PUBLIC DISPATCH
    # =========================================

    def dispatch(
        self,
        plan,
        incident,
    ):

        if not isinstance(
            plan,
            dict,
        ):
            return []

        channels = plan.get(
            "channels",
            [],
        )

        if not isinstance(
            channels,
            (
                list,
                tuple,
            ),
        ):
            return []

        outcomes = []

        for channel in channels:

            outcomes.append(
                self._dispatch_channel(
                    channel=channel,
                    plan=plan,
                    incident=incident,
                )
            )

        return outcomes

    # =========================================
    # CHANNEL DELIVERY
    # =========================================

    def _dispatch_channel(
        self,
        channel,
        plan,
        incident,
    ):

        dedup_key = plan.get(
            "dedup_key"
        )

        claimed = self._claim(
            dedup_key=dedup_key,
            channel=channel,
            plan=plan,
        )

        if claimed is False:

            return {
                "channel": channel,
                "status": "SUPPRESSED",
                "reason": (
                    "Notification delivery "
                    "already claimed or delivered"
                ),
            }

        if isinstance(
            claimed,
            dict,
        ):

            return claimed

        adapter = self.adapters.get(
            channel
        )

        if adapter is None:

            reason = (
                "Notification adapter "
                "is not configured"
            )

            self._mark_skipped(
                dedup_key=dedup_key,
                channel=channel,
                reason=reason,
            )

            return {
                "channel": channel,
                "status": "SKIPPED",
                "reason": reason,
            }

        try:

            result = adapter.send(
                plan,
                incident,
            )

            if isinstance(
                result,
                dict,
            ):

                normalized = dict(
                    result
                )

                normalized.setdefault(
                    "channel",
                    channel,
                )

                normalized.setdefault(
                    "status",
                    "SUCCESS",
                )

            else:

                normalized = {
                    "channel": channel,
                    "status": "SUCCESS",
                }

            status = normalized.get(
                "status"
            )

            if status == "SUCCESS":

                store_error = (
                    self._mark_success(
                        dedup_key=dedup_key,
                        channel=channel,
                        backend=normalized.get(
                            "backend"
                        ),
                    )
                )

                if store_error is not None:

                    return {
                        "channel": channel,
                        "status": "FAILED",
                        "backend": (
                            "dedup_store"
                        ),
                        "error": store_error,
                    }

            elif status == "SKIPPED":

                self._mark_skipped(
                    dedup_key=dedup_key,
                    channel=channel,
                    reason=normalized.get(
                        "reason",
                        "Adapter skipped delivery",
                    ),
                )

            else:

                self._mark_failed(
                    dedup_key=dedup_key,
                    channel=channel,
                    error=normalized.get(
                        "error",
                        (
                            "Adapter returned "
                            f"status={status}"
                        ),
                    ),
                    backend=normalized.get(
                        "backend"
                    ),
                )

            return normalized

        except Exception as error:

            self._mark_failed(
                dedup_key=dedup_key,
                channel=channel,
                error=error,
                backend=(
                    type(adapter).__name__
                ),
            )

            return {
                "channel": channel,
                "status": "FAILED",
                "error": str(
                    error
                ),
            }

    # =========================================
    # DURABLE DEDUP
    # =========================================

    def _claim(
        self,
        dedup_key,
        channel,
        plan,
    ):

        repository = (
            self.delivery_repository
        )

        if repository is None:
            return True

        if not dedup_key:

            return {
                "channel": channel,
                "status": "FAILED",
                "backend": "dedup_store",
                "error": (
                    "Missing notification "
                    "dedup_key"
                ),
            }

        try:

            claim_delivery = getattr(
                repository,
                "claim_delivery",
                None,
            )

            if claim_delivery is None:

                return repository.claim(
                    dedup_key=dedup_key,
                    channel=channel,
                    incident_id=plan.get(
                        "incident_id"
                    ),
                    severity=plan.get(
                        "severity"
                    ),
                )

            decision = claim_delivery(
                dedup_key=dedup_key,
                channel=channel,
                incident_id=plan.get(
                    "incident_id"
                ),
                severity=plan.get(
                    "severity"
                ),
            )

            status = decision.get(
                "status"
            )

            if status == "CLAIMED":
                return True

            if status == "DEFERRED":

                return {
                    "channel": channel,
                    "status": "DEFERRED",
                    "reason": decision.get(
                        "reason",
                        (
                            "Notification retry "
                            "backoff active"
                        ),
                    ),
                    "retry_at": decision.get(
                        "retry_at"
                    ),
                    "attempt_count": (
                        decision.get(
                            "attempt_count"
                        )
                    ),
                }

            return {
                "channel": channel,
                "status": "SUPPRESSED",
                "reason": decision.get(
                    "reason",
                    (
                        "Notification delivery "
                        "already claimed or delivered"
                    ),
                ),
            }

        except Exception as error:

            return {
                "channel": channel,
                "status": "FAILED",
                "backend": "dedup_store",
                "error": str(
                    error
                ),
            }

    def _mark_success(
        self,
        dedup_key,
        channel,
        backend,
    ):

        repository = (
            self.delivery_repository
        )

        if repository is None:
            return None

        try:

            changed = repository.mark_success(
                dedup_key=dedup_key,
                channel=channel,
                backend=backend,
            )

            if not changed:

                return (
                    "Unable to persist "
                    "SUCCESS delivery state"
                )

        except Exception as error:

            return str(
                error
            )

        return None

    def _mark_failed(
        self,
        dedup_key,
        channel,
        error,
        backend=None,
    ):

        repository = (
            self.delivery_repository
        )

        if (
            repository is None
            or not dedup_key
        ):
            return

        try:

            repository.mark_failed(
                dedup_key=dedup_key,
                channel=channel,
                error=error,
                backend=backend,
            )

        except Exception:

            # Notification state failures must
            # never escape into incident flow.
            pass

    def _mark_skipped(
        self,
        dedup_key,
        channel,
        reason,
    ):

        repository = (
            self.delivery_repository
        )

        if (
            repository is None
            or not dedup_key
        ):
            return

        try:

            repository.mark_skipped(
                dedup_key=dedup_key,
                channel=channel,
                reason=reason,
            )

        except Exception:

            # Same failure-isolation contract.
            pass
