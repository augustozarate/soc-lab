import asyncio
import ssl

import aiohttp

from threema.gateway.exception import (
    GatewayError,
    MessageServerError,
)

from engine.services.threema_connection_factory import (
    ThreemaSecureConnectionFactory,
)

from engine.services.threema_e2e_client import (
    ThreemaE2EClient,
)

from engine.services.threema_message_builder import (
    ThreemaMessageBuilder,
)


class ThreemaNotificationAdapter:

    BACKEND = "threema_gateway"

    def __init__(
        self,
        gateway_id=None,
        api_secret=None,
        private_key_file=None,
        recipient_id=None,
        recipient_public_key=None,
        timeout_seconds=5,
        message_builder=None,
        connection_factory=None,
        client_class=None,
    ):

        self.message_builder = (
            message_builder
            or ThreemaMessageBuilder()
        )

        self.recipient_id = (
            recipient_id
        )

        self.recipient_public_key = (
            recipient_public_key
        )

        self.client_class = (
            client_class
            or ThreemaE2EClient
        )

        if connection_factory is None:

            connection_factory = (
                ThreemaSecureConnectionFactory(
                    gateway_id=gateway_id,
                    api_secret=api_secret,
                    private_key_file=(
                        private_key_file
                    ),
                    timeout_seconds=(
                        timeout_seconds
                    ),
                )
            )

        self.connection_factory = (
            connection_factory
        )

    # =========================================
    # PUBLIC
    # =========================================

    def send(
        self,
        plan,
        incident,
    ):

        text = (
            self.message_builder
            .build(
                plan,
                incident,
            )
        )

        # NotificationService currently invokes
        # adapters synchronously. Refuse nested
        # event-loop execution before creating a
        # coroutine, avoiding un-awaited coroutine
        # warnings and ambiguous delivery state.
        try:

            asyncio.get_running_loop()

        except RuntimeError:

            pass

        else:

            raise RuntimeError(
                "Threema delivery failed: "
                "async context conflict"
            )

        try:

            asyncio.run(
                self._deliver(
                    text
                )
            )

        except MessageServerError as error:

            return self._provider_result(
                error.status
            )

        except (
            aiohttp.ClientSSLError,
            ssl.SSLError,
        ):

            raise RuntimeError(
                "Threema delivery failed: "
                "TLS error"
            ) from None

        except asyncio.TimeoutError:

            raise RuntimeError(
                "Threema delivery failed: "
                "timeout"
            ) from None

        except aiohttp.ClientConnectionError:

            raise RuntimeError(
                "Threema delivery failed: "
                "connection error"
            ) from None

        except aiohttp.ClientError:

            raise RuntimeError(
                "Threema delivery failed: "
                "HTTP client error"
            ) from None

        except GatewayError:

            raise RuntimeError(
                "Threema delivery failed: "
                "SDK error"
            ) from None

        except (
            ValueError,
            TypeError,
        ):

            raise RuntimeError(
                "Threema delivery failed: "
                "configuration error"
            ) from None

        except RuntimeError:

            raise RuntimeError(
                "Threema delivery failed: "
                "internal error"
            ) from None

        except Exception:

            raise RuntimeError(
                "Threema delivery failed: "
                "internal error"
            ) from None

        return {
            "channel": "threema",
            "status": "SUCCESS",
            "backend": self.BACKEND,
        }

    # =========================================
    # ASYNC DELIVERY
    # =========================================

    async def _deliver(
        self,
        text,
    ):

        connection = None

        try:

            connection = (
                self.connection_factory
                .build()
            )

            client = self.client_class(
                connection=connection,
                recipient_id=(
                    self.recipient_id
                ),
                recipient_public_key=(
                    self.recipient_public_key
                ),
            )

            return await client.send_text(
                text
            )

        finally:

            if connection is not None:

                try:

                    await connection.close()

                except Exception:

                    # A provider acknowledgement may
                    # already have been returned.
                    # Never turn a cleanup failure into
                    # a retryable delivery failure and
                    # risk duplicate notification.
                    pass

    # =========================================
    # PROVIDER RESULT
    # =========================================

    def _provider_result(
        self,
        status,
    ):

        try:

            status = int(
                status
            )

        except (
            TypeError,
            ValueError,
        ):

            raise RuntimeError(
                "Threema delivery failed: "
                "provider rejection"
            ) from None

        if status == 429:

            return {
                "channel": "threema",
                "status": "RATE_LIMITED",
                "backend": self.BACKEND,
                "http_status": 429,
                "reason": (
                    "Threema delivery "
                    "rate limited"
                ),
            }

        reasons = {
            400: (
                "invalid request"
            ),
            401: (
                "authentication error"
            ),
            402: (
                "credits exhausted"
            ),
            404: (
                "provider rejection"
            ),
            413: (
                "payload too large"
            ),
            500: (
                "provider unavailable"
            ),
        }

        reason = reasons.get(
            status,
            "provider rejection",
        )

        raise RuntimeError(
            "Threema delivery failed: "
            + reason
        )
