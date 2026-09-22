import json

from urllib.parse import (
    urlparse,
)

import requests

from engine.services.webhook_payload_builder import (
    WebhookPayloadBuilder,
)


class WebhookNotificationAdapter:

    def __init__(
        self,
        url,
        timeout_seconds=5,
        max_payload_bytes=16384,
        payload_builder=None,
        post=None,
    ):

        self.url = self._validate_url(
            url
        )

        if timeout_seconds <= 0:

            raise ValueError(
                "timeout_seconds must be "
                "greater than 0"
            )

        if max_payload_bytes <= 0:

            raise ValueError(
                "max_payload_bytes must be "
                "greater than 0"
            )

        self.timeout_seconds = float(
            timeout_seconds
        )

        self.max_payload_bytes = int(
            max_payload_bytes
        )

        self.payload_builder = (
            payload_builder
            or WebhookPayloadBuilder()
        )

        self.post = (
            post
            or requests.post
        )

    # =========================================
    # VALIDATION
    # =========================================

    def _validate_url(
        self,
        url,
    ):

        if not isinstance(
            url,
            str,
        ):

            raise TypeError(
                "Webhook URL must be a string"
            )

        value = url.strip()

        if not value:

            raise ValueError(
                "Webhook URL is required"
            )

        parsed = urlparse(
            value
        )

        if parsed.scheme.lower() != "https":

            raise ValueError(
                "Webhook URL must use HTTPS"
            )

        if not parsed.hostname:

            raise ValueError(
                "Webhook URL must include "
                "a hostname"
            )

        if (
            parsed.username is not None
            or parsed.password is not None
        ):

            raise ValueError(
                "Webhook URL must not contain "
                "embedded credentials"
            )

        return value

    # =========================================
    # DELIVERY
    # =========================================

    def send(
        self,
        plan,
        incident,
    ):

        payload = self.payload_builder.build(
            plan,
            incident,
        )

        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(
                ",",
                ":",
            ),
            ensure_ascii=False,
            default=str,
        ).encode(
            "utf-8"
        )

        if (
            len(encoded)
            > self.max_payload_bytes
        ):

            raise RuntimeError(
                "Webhook request failed: "
                "payload too large"
            )

        try:

            response = self.post(
                self.url,
                json=payload,
                headers={
                    "Content-Type": (
                        "application/json"
                    ),
                },
                timeout=(
                    self.timeout_seconds
                ),
                allow_redirects=False,
                verify=True,
            )

        except requests.exceptions.Timeout:

            raise RuntimeError(
                "Webhook request failed: timeout"
            ) from None

        except requests.exceptions.SSLError:

            raise RuntimeError(
                "Webhook request failed: TLS error"
            ) from None

        except requests.exceptions.ConnectionError:

            raise RuntimeError(
                "Webhook request failed: "
                "connection error"
            ) from None

        except requests.exceptions.RequestException:

            raise RuntimeError(
                "Webhook request failed: "
                "HTTP client error"
            ) from None

        status_code = int(
            response.status_code
        )

        if not (
            200
            <= status_code
            < 300
        ):

            raise RuntimeError(
                "Webhook request failed: "
                f"HTTP {status_code}"
            )

        return {
            "channel": "webhook",
            "status": "SUCCESS",
            "backend": "https",
            "http_status": (
                status_code
            ),
        }
