class NotificationChannelReadModel:

    CHANNEL_ORDER = (
        "local",
        "email",
        "telegram",
        "webhook",
        "threema",
    )

    def __init__(
        self,
        local_available,
        email_available,
        telegram_available,
        webhook_available,
        threema_available,
        threema_policy_enabled,
    ):
        self.local_available = bool(
            local_available
        )
        self.email_available = bool(
            email_available
        )
        self.telegram_available = bool(
            telegram_available
        )
        self.webhook_available = bool(
            webhook_available
        )
        self.threema_available = bool(
            threema_available
        )
        self.threema_policy_enabled = bool(
            threema_policy_enabled
        )

    def snapshot(self):
        return {
            "local": self._availability_status(
                self.local_available
            ),
            "email": self._availability_status(
                self.email_available
            ),
            "telegram": self._availability_status(
                self.telegram_available
            ),
            "webhook": self._availability_status(
                self.webhook_available
            ),
            "threema": (
                self._threema_status()
            ),
        }

    @staticmethod
    def _availability_status(
        available,
    ):
        return (
            "READY"
            if available
            else "DISABLED"
        )

    def _threema_status(self):
        if not self.threema_available:
            return "DISABLED"

        if not self.threema_policy_enabled:
            return "INERT"

        return "READY"
