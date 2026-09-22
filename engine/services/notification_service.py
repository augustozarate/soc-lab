import time

from engine.telemetry.metrics import metrics


class NotificationService:

    def __init__(
        self,
        adapters=None,
        delivery_repository=None,
        rate_limit_repository=None,
        metrics_collector=None,
    ):

        self.adapters = dict(
            adapters or {}
        )

        self.delivery_repository = (
            delivery_repository
        )

        self.rate_limit_repository = (
            rate_limit_repository
        )

        self.metrics = (
            metrics
            if metrics_collector is None
            else metrics_collector
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

            outcome = self._dispatch_channel(
                channel=channel,
                plan=plan,
                incident=incident,
            )

            outcomes.append(
                outcome
            )

            self._record_outcome(
                outcome
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

        if self._channel_is_disabled(
            channel
        ):

            return {
                "channel": channel,
                "status": "SKIPPED",
                "reason": (
                    "Notification channel "
                    "is disabled by configuration"
                ),
            }

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

        rate_decision = self._check_rate_limit(
            channel
        )

        if (
            rate_decision is not None
            and rate_decision.get(
                "status"
            )
            == "RATE_LIMITED"
        ):

            reason = rate_decision.get(
                "reason",
                (
                    "Notification channel "
                    "rate limit reached"
                ),
            )

            self._mark_rate_limited(
                dedup_key=dedup_key,
                channel=channel,
                reason=reason,
            )

            return {
                "channel": channel,
                "status": "RATE_LIMITED",
                "reason": reason,
                "reset_at": (
                    rate_decision.get(
                        "reset_at"
                    )
                ),
            }

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

        self._record_attempt(
            channel
        )

        started = time.monotonic()

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

            elif status == "RATE_LIMITED":

                self._mark_rate_limited(
                    dedup_key=dedup_key,
                    channel=channel,
                    reason=normalized.get(
                        "reason",
                        (
                            "Notification provider "
                            "rate limit reached"
                        ),
                    ),
                    retry_after_seconds=(
                        normalized.get(
                            "retry_after_seconds"
                        )
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

        finally:

            self._observe_latency(
                channel=channel,
                value=(
                    time.monotonic()
                    - started
                ),
            )

    # =========================================
    # TELEMETRY
    # =========================================

    def _metric_channel(
        self,
        channel,
    ):

        if channel in {
            "local",
            "email",
            "telegram",
            "webhook",
        }:

            return channel

        return "other"

    def _increment(
        self,
        metric,
        channel,
    ):

        collector = self.metrics

        if collector is None:
            return

        safe_channel = (
            self._metric_channel(
                channel
            )
        )

        try:

            # Global bounded metric.
            collector.inc(
                metric
            )

            # Per-channel dimensions remain
            # bounded to five possible suffixes.
            collector.inc(
                f"{metric}."
                f"{safe_channel}"
            )

        except Exception:

            # Telemetry must never affect
            # notification delivery.
            pass

    def _record_attempt(
        self,
        channel,
    ):

        self._increment(
            "notification_delivery_"
            "attempts_total",
            channel,
        )

    def _record_outcome(
        self,
        outcome,
    ):

        if not isinstance(
            outcome,
            dict,
        ):
            return

        channel = outcome.get(
            "channel",
            "other",
        )

        status = str(
            outcome.get(
                "status",
                "",
            )
        ).strip().upper()

        metric_by_status = {
            "SUCCESS": (
                "notification_delivery_"
                "success_total"
            ),
            "FAILED": (
                "notification_delivery_"
                "failed_total"
            ),
            "SKIPPED": (
                "notification_delivery_"
                "skipped_total"
            ),
            "SUPPRESSED": (
                "notification_delivery_"
                "suppressed_total"
            ),
            "DEFERRED": (
                "notification_delivery_"
                "deferred_total"
            ),
            "RATE_LIMITED": (
                "notification_delivery_"
                "rate_limited_total"
            ),
        }

        metric = metric_by_status.get(
            status
        )

        if metric is None:
            return

        self._increment(
            metric,
            channel,
        )

    def _observe_latency(
        self,
        channel,
        value,
    ):

        collector = self.metrics

        if collector is None:
            return

        try:

            collector.observe(
                "notification_delivery_"
                "latency_seconds",
                value,
                label=(
                    self._metric_channel(
                        channel
                    )
                ),
            )

        except Exception:

            # Metrics failure isolation.
            pass

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

    def _channel_is_disabled(
        self,
        channel,
    ):

        repository = (
            self.rate_limit_repository
        )

        if repository is None:
            return False

        checker = getattr(
            repository,
            "is_disabled",
            None,
        )

        if checker is None:
            return False

        try:

            return bool(
                checker(
                    channel
                )
            )

        except Exception:

            # Configuration preflight failure must
            # not silently disable a notification.
            return False

    def _check_rate_limit(
        self,
        channel,
    ):

        repository = (
            self.rate_limit_repository
        )

        if repository is None:
            return None

        try:

            return (
                repository
                .check_and_consume(
                    channel
                )
            )

        except Exception as error:

            return {
                "status": "RATE_LIMITED",
                "reason": (
                    "Rate limit store failure: "
                    f"{error}"
                ),
            }

    def _mark_rate_limited(
        self,
        dedup_key,
        channel,
        reason,
        retry_after_seconds=None,
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

            kwargs = {
                "dedup_key": dedup_key,
                "channel": channel,
                "reason": reason,
            }

            if retry_after_seconds is not None:

                kwargs[
                    "retry_after_seconds"
                ] = retry_after_seconds

            repository.mark_rate_limited(
                **kwargs
            )

        except Exception:
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
