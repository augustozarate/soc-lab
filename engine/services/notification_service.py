class NotificationService:

    def __init__(
        self,
        adapters=None,
    ):

        self.adapters = dict(
            adapters or {}
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
    # CHANNEL ISOLATION
    # =========================================

    def _dispatch_channel(
        self,
        channel,
        plan,
        incident,
    ):

        adapter = self.adapters.get(
            channel
        )

        if adapter is None:

            return {
                "channel": channel,
                "status": "SKIPPED",
                "reason": (
                    "Notification adapter "
                    "is not configured"
                ),
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

                return normalized

            return {
                "channel": channel,
                "status": "SUCCESS",
            }

        except Exception as error:

            return {
                "channel": channel,
                "status": "FAILED",
                "error": str(
                    error
                ),
            }
