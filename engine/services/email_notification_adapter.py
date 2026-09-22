import smtplib
import socket
import ssl

from email.utils import (
    parseaddr,
)

from engine.services.email_message_builder import (
    EmailMessageBuilder,
)


class EmailNotificationAdapter:

    def __init__(
        self,
        host,
        port,
        security,
        timeout_seconds,
        sender,
        recipient,
        username=None,
        password=None,
        ca_bundle=None,
        message_builder=None,
        smtp_ssl_factory=None,
        smtp_factory=None,
        ssl_context_factory=None,
    ):

        self.host = self._validate_host(
            host
        )

        self.port = self._validate_port(
            port
        )

        self.security = (
            self._validate_security(
                security
            )
        )

        self.timeout_seconds = (
            self._validate_timeout(
                timeout_seconds
            )
        )

        self.sender = (
            self._validate_address(
                sender,
                "sender",
            )
        )

        self.recipient = (
            self._validate_address(
                recipient,
                "recipient",
            )
        )

        (
            self.username,
            self.password,
        ) = self._validate_credentials(
            username,
            password,
        )

        self.ca_bundle = (
            self._validate_ca_bundle(
                ca_bundle
            )
        )

        self.message_builder = (
            message_builder
            or EmailMessageBuilder(
                sender=self.sender,
                recipient=self.recipient,
            )
        )

        self.smtp_ssl_factory = (
            smtp_ssl_factory
            or smtplib.SMTP_SSL
        )

        self.smtp_factory = (
            smtp_factory
            or smtplib.SMTP
        )

        self.ssl_context_factory = (
            ssl_context_factory
            or ssl.create_default_context
        )

    # =========================================
    # VALIDATION
    # =========================================

    def _validate_host(
        self,
        value,
    ):

        if not isinstance(
            value,
            str,
        ):

            raise TypeError(
                "SMTP host must be a string"
            )

        value = value.strip()

        if not value:

            raise ValueError(
                "SMTP host is required"
            )

        if (
            "\r" in value
            or "\n" in value
        ):

            raise ValueError(
                "SMTP host contains "
                "invalid characters"
            )

        return value

    def _validate_port(
        self,
        value,
    ):

        try:

            value = int(
                value
            )

        except (
            TypeError,
            ValueError,
        ):

            raise ValueError(
                "SMTP port must be an integer"
            ) from None

        if not (
            1
            <= value
            <= 65535
        ):

            raise ValueError(
                "SMTP port must be between "
                "1 and 65535"
            )

        return value

    def _validate_security(
        self,
        value,
    ):

        if not isinstance(
            value,
            str,
        ):

            raise TypeError(
                "SMTP security mode "
                "must be a string"
            )

        value = (
            value
            .strip()
            .lower()
        )

        if value not in {
            "ssl",
            "starttls",
        }:

            raise ValueError(
                "SMTP security mode must be "
                "ssl or starttls"
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
                "SMTP timeout must be numeric"
            ) from None

        if value <= 0:

            raise ValueError(
                "SMTP timeout must be "
                "greater than 0"
            )

        return value

    def _validate_address(
        self,
        value,
        label,
    ):

        if not isinstance(
            value,
            str,
        ):

            raise TypeError(
                f"SMTP {label} address "
                "must be a string"
            )

        value = value.strip()

        if (
            not value
            or "\r" in value
            or "\n" in value
        ):

            raise ValueError(
                f"SMTP {label} address "
                "is invalid"
            )

        display_name, address = parseaddr(
            value
        )

        if (
            display_name
            or address != value
            or "@" not in address
        ):

            raise ValueError(
                f"SMTP {label} address "
                "is invalid"
            )

        local, domain = address.rsplit(
            "@",
            1,
        )

        if (
            not local
            or not domain
            or "." not in domain
        ):

            raise ValueError(
                f"SMTP {label} address "
                "is invalid"
            )

        return address

    def _validate_credentials(
        self,
        username,
        password,
    ):

        if username is None:
            username = ""

        if password is None:
            password = ""

        if not isinstance(
            username,
            str,
        ):

            raise TypeError(
                "SMTP username must "
                "be a string"
            )

        if not isinstance(
            password,
            str,
        ):

            raise TypeError(
                "SMTP password must "
                "be a string"
            )

        username = username.strip()

        if (
            "\r" in username
            or "\n" in username
        ):

            raise ValueError(
                "SMTP username contains "
                "invalid characters"
            )

        if bool(
            username
        ) != bool(
            password
        ):

            raise ValueError(
                "SMTP username and password "
                "must be configured together"
            )

        return (
            username or None,
            password or None,
        )

    def _validate_ca_bundle(
        self,
        value,
    ):

        if value is None:
            return None

        if not isinstance(
            value,
            str,
        ):

            raise TypeError(
                "SMTP CA bundle must "
                "be a string path"
            )

        value = value.strip()

        return value or None

    # =========================================
    # TLS
    # =========================================

    def _tls_context(
        self,
    ):

        if self.ca_bundle:

            return (
                self.ssl_context_factory(
                    cafile=self.ca_bundle
                )
            )

        return (
            self.ssl_context_factory()
        )

    # =========================================
    # DELIVERY
    # =========================================

    def send(
        self,
        plan,
        incident,
    ):

        message = (
            self.message_builder
            .build(
                plan,
                incident,
            )
        )

        try:

            if self.security == "ssl":

                self._send_ssl(
                    message
                )

                backend = "smtp_ssl"

            else:

                self._send_starttls(
                    message
                )

                backend = (
                    "smtp_starttls"
                )

        except smtplib.SMTPAuthenticationError:

            raise RuntimeError(
                "Email delivery failed: "
                "authentication error"
            ) from None

        except smtplib.SMTPNotSupportedError:

            raise RuntimeError(
                "Email delivery failed: "
                "TLS error"
            ) from None

        except ssl.SSLError:

            raise RuntimeError(
                "Email delivery failed: "
                "TLS error"
            ) from None

        except (
            TimeoutError,
            socket.timeout,
        ):

            raise RuntimeError(
                "Email delivery failed: "
                "timeout"
            ) from None

        except (
            smtplib.SMTPConnectError,
            smtplib.SMTPServerDisconnected,
        ):

            raise RuntimeError(
                "Email delivery failed: "
                "connection error"
            ) from None

        except (
            smtplib.SMTPRecipientsRefused,
            smtplib.SMTPSenderRefused,
            smtplib.SMTPDataError,
            smtplib.SMTPHeloError,
        ):

            raise RuntimeError(
                "Email delivery failed: "
                "SMTP rejection"
            ) from None

        except smtplib.SMTPException:

            raise RuntimeError(
                "Email delivery failed: "
                "SMTP error"
            ) from None

        except OSError:

            raise RuntimeError(
                "Email delivery failed: "
                "connection error"
            ) from None

        return {
            "channel": "email",
            "status": "SUCCESS",
            "backend": backend,
        }

    def _send_ssl(
        self,
        message,
    ):

        context = self._tls_context()

        with self.smtp_ssl_factory(
            self.host,
            self.port,
            timeout=self.timeout_seconds,
            context=context,
        ) as client:

            self._authenticate(
                client
            )

            client.send_message(
                message,
                from_addr=self.sender,
                to_addrs=[
                    self.recipient
                ],
            )

    def _send_starttls(
        self,
        message,
    ):

        context = self._tls_context()

        with self.smtp_factory(
            self.host,
            self.port,
            timeout=self.timeout_seconds,
        ) as client:

            client.ehlo()

            client.starttls(
                context=context
            )

            client.ehlo()

            self._authenticate(
                client
            )

            client.send_message(
                message,
                from_addr=self.sender,
                to_addrs=[
                    self.recipient
                ],
            )

    def _authenticate(
        self,
        client,
    ):

        if self.username is None:
            return

        client.login(
            self.username,
            self.password,
        )
