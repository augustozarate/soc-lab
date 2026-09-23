import asyncio

from threema.gateway import e2e
from threema.gateway.key import Key


class ThreemaE2EClient:

    def __init__(
        self,
        connection,
        recipient_id,
        recipient_public_key,
        message_class=None,
    ):

        if connection is None:

            raise ValueError(
                "Threema connection is required"
            )

        if getattr(
            connection,
            "blocking",
            None,
        ) is not True:

            raise ValueError(
                "Threema connection must use "
                "blocking mode"
            )

        self.connection = connection

        self.recipient_id = (
            self._validate_recipient_id(
                recipient_id
            )
        )

        self.recipient_public_key = (
            self._decode_public_key(
                recipient_public_key
            )
        )

        self.message_class = (
            message_class
            or e2e.TextMessage
        )

    # =========================================
    # VALIDATION
    # =========================================

    def _validate_recipient_id(
        self,
        value,
    ):

        if not isinstance(
            value,
            str,
        ):

            raise TypeError(
                "Threema recipient ID "
                "must be a string"
            )

        value = value.strip()

        if not value:

            raise ValueError(
                "Threema recipient ID "
                "is required"
            )

        if (
            "\r" in value
            or "\n" in value
        ):

            raise ValueError(
                "Threema recipient ID "
                "contains invalid characters"
            )

        if len(value) != 8:

            raise ValueError(
                "Threema recipient ID "
                "must contain 8 characters"
            )

        return value

    def _decode_public_key(
        self,
        value,
    ):

        if not isinstance(
            value,
            str,
        ):

            raise TypeError(
                "Threema recipient public key "
                "must be a string"
            )

        value = value.strip()

        if not value:

            raise ValueError(
                "Threema recipient public key "
                "is required"
            )

        if (
            "\r" in value
            or "\n" in value
        ):

            raise ValueError(
                "Threema recipient public key "
                "contains invalid characters"
            )

        try:

            return Key.decode(
                value,
                Key.Type.public,
            )

        except Exception:

            raise ValueError(
                "Invalid Threema recipient "
                "public key"
            ) from None

    # =========================================
    # DELIVERY
    # =========================================

    def send_text(
        self,
        text,
    ):

        if not isinstance(
            text,
            str,
        ):

            raise TypeError(
                "Threema message text "
                "must be a string"
            )

        if not text:

            raise ValueError(
                "Threema message text "
                "must not be empty"
            )

        return self._run_blocking_sdk_call(
            lambda: self._send_text(
                text
            )
        )

    def _send_text(
        self,
        text,
    ):

        message = self.message_class(
            self.connection,
            to_id=self.recipient_id,
            key=self.recipient_public_key,
            text=text,
        )

        return message.send()

    # =========================================
    # SDK SYNC BOUNDARY
    # =========================================

    def _run_blocking_sdk_call(
        self,
        operation,
    ):

        try:

            asyncio.get_running_loop()

        except RuntimeError:

            pass

        else:

            raise RuntimeError(
                "Threema blocking SDK cannot "
                "run inside an active event loop"
            )

        loop = asyncio.new_event_loop()

        try:

            asyncio.set_event_loop(
                loop
            )

            return operation()

        finally:

            asyncio.set_event_loop(
                None
            )

            loop.close()
