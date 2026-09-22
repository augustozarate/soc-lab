from urllib.parse import (
    urlparse,
)

import requests

from engine.services.telegram_message_builder import (
    TelegramMessageBuilder,
)


class TelegramNotificationAdapter:

    DEFAULT_API_BASE_URL = (
        "https://api.telegram.org"
    )

    MAX_RETRY_AFTER_SECONDS = 86400

    def __init__(
        self,
        bot_token,
        chat_id,
        timeout_seconds=5,
        max_message_chars=3500,
        ca_bundle=None,
        message_builder=None,
        post=None,
        api_base_url=None,
    ):

        self.bot_token = (
            self._validate_secret(
                bot_token,
                "Telegram bot token",
            )
        )

        self.chat_id = (
            self._validate_chat_id(
                chat_id
            )
        )

        self.timeout_seconds = (
            self._validate_timeout(
                timeout_seconds
            )
        )

        self.verify = (
            self._validate_ca_bundle(
                ca_bundle
            )
        )

        self.api_base_url = (
            self._validate_base_url(
                api_base_url
                or self.DEFAULT_API_BASE_URL
            )
        )

        self.message_builder = (
            message_builder
            or TelegramMessageBuilder(
                max_chars=(
                    max_message_chars
                )
            )
        )

        self.post = (
            post
            or requests.post
        )

    # =========================================
    # VALIDATION
    # =========================================

    def _validate_secret(
        self,
        value,
        label,
    ):

        if not isinstance(
            value,
            str,
        ):

            raise TypeError(
                f"{label} must be a string"
            )

        value = value.strip()

        if not value:

            raise ValueError(
                f"{label} is required"
            )

        if (
            "\r" in value
            or "\n" in value
        ):

            raise ValueError(
                f"{label} contains "
                "invalid characters"
            )

        return value

    def _validate_chat_id(
        self,
        value,
    ):

        if isinstance(
            value,
            int,
        ):

            value = str(
                value
            )

        if not isinstance(
            value,
            str,
        ):

            raise TypeError(
                "Telegram chat_id "
                "must be a string or integer"
            )

        value = value.strip()

        if not value:

            raise ValueError(
                "Telegram chat_id "
                "is required"
            )

        if (
            "\r" in value
            or "\n" in value
        ):

            raise ValueError(
                "Telegram chat_id contains "
                "invalid characters"
            )

        return value

    def _validate_timeout(
        self,
        value,
    ):

        try:

            value = float(
                value
            )

        except (
            TypeError,
            ValueError,
        ):

            raise ValueError(
                "Telegram timeout "
                "must be numeric"
            ) from None

        if value <= 0:

            raise ValueError(
                "Telegram timeout "
                "must be greater than 0"
            )

        return value

    def _validate_ca_bundle(
        self,
        value,
    ):

        if value is None:
            return True

        if not isinstance(
            value,
            str,
        ):

            raise TypeError(
                "Telegram CA bundle "
                "must be a string path"
            )

        value = value.strip()

        if not value:
            return True

        return value

    def _validate_base_url(
        self,
        value,
    ):

        if not isinstance(
            value,
            str,
        ):

            raise TypeError(
                "Telegram API base URL "
                "must be a string"
            )

        value = value.strip()

        if not value:

            raise ValueError(
                "Telegram API base URL "
                "is required"
            )

        parsed = urlparse(
            value
        )

        if parsed.scheme.lower() != "https":

            raise ValueError(
                "Telegram API base URL "
                "must use HTTPS"
            )

        if not parsed.hostname:

            raise ValueError(
                "Telegram API base URL "
                "must include a hostname"
            )

        if (
            parsed.username is not None
            or parsed.password is not None
        ):

            raise ValueError(
                "Telegram API base URL "
                "must not contain credentials"
            )

        if (
            parsed.query
            or parsed.fragment
        ):

            raise ValueError(
                "Telegram API base URL "
                "must not contain query "
                "or fragment components"
            )

        return value.rstrip(
            "/"
        )

    # =========================================
    # ENDPOINT
    # =========================================

    def _endpoint(
        self,
    ):

        return (
            f"{self.api_base_url}"
            f"/bot{self.bot_token}"
            "/sendMessage"
        )

    # =========================================
    # PROVIDER RETRY
    # =========================================

    def _retry_after_seconds(
        self,
        response,
    ):

        try:

            body = response.json()

        except (
            ValueError,
            TypeError,
        ):

            return None

        if not isinstance(
            body,
            dict,
        ):

            return None

        parameters = body.get(
            "parameters"
        )

        if not isinstance(
            parameters,
            dict,
        ):

            return None

        value = parameters.get(
            "retry_after"
        )

        if (
            isinstance(
                value,
                bool,
            )
            or not isinstance(
                value,
                int,
            )
        ):

            return None

        if not (
            1
            <= value
            <= self.MAX_RETRY_AFTER_SECONDS
        ):

            return None

        return value

    # =========================================
    # DELIVERY
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

        payload = {
            "chat_id": (
                self.chat_id
            ),
            "text": text,
        }

        try:

            response = self.post(
                self._endpoint(),
                json=payload,
                timeout=(
                    self.timeout_seconds
                ),
                allow_redirects=False,
                verify=self.verify,
            )

        except requests.exceptions.Timeout:

            raise RuntimeError(
                "Telegram delivery failed: "
                "timeout"
            ) from None

        except requests.exceptions.SSLError:

            raise RuntimeError(
                "Telegram delivery failed: "
                "TLS error"
            ) from None

        except requests.exceptions.ConnectionError:

            raise RuntimeError(
                "Telegram delivery failed: "
                "connection error"
            ) from None

        except requests.exceptions.RequestException:

            raise RuntimeError(
                "Telegram delivery failed: "
                "HTTP client error"
            ) from None

        status_code = int(
            response.status_code
        )

        if status_code in {
            401,
            403,
        }:

            raise RuntimeError(
                "Telegram delivery failed: "
                "authentication error"
            )

        if status_code == 429:

            retry_after = (
                self._retry_after_seconds(
                    response
                )
            )

            result = {
                "channel": "telegram",
                "status": "RATE_LIMITED",
                "backend": (
                    "telegram_bot_api"
                ),
                "http_status": 429,
                "reason": (
                    "Telegram delivery "
                    "rate limited"
                ),
            }

            if retry_after is not None:

                result[
                    "retry_after_seconds"
                ] = retry_after

            return result

        if not (
            200
            <= status_code
            < 300
        ):

            raise RuntimeError(
                "Telegram delivery failed: "
                "API rejection"
            )

        try:

            body = response.json()

        except (
            ValueError,
            TypeError,
        ):

            raise RuntimeError(
                "Telegram delivery failed: "
                "API rejection"
            ) from None

        if not isinstance(
            body,
            dict,
        ):

            raise RuntimeError(
                "Telegram delivery failed: "
                "API rejection"
            )

        if body.get(
            "ok"
        ) is not True:

            raise RuntimeError(
                "Telegram delivery failed: "
                "API rejection"
            )

        return {
            "channel": "telegram",
            "status": "SUCCESS",
            "backend": (
                "telegram_bot_api"
            ),
            "http_status": (
                status_code
            ),
        }
