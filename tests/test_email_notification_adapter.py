import smtplib
import ssl

from engine.services.email_notification_adapter import (
    EmailNotificationAdapter,
)


class FakeContext:

    pass


class TLSContextFactory:

    def __init__(
        self,
    ):

        self.calls = []

    def __call__(
        self,
        **kwargs,
    ):

        self.calls.append(
            kwargs
        )

        return FakeContext()


class FakeSMTP:

    def __init__(
        self,
        error=None,
    ):

        self.error = error
        self.events = []
        self.login_args = None
        self.message = None
        self.from_addr = None
        self.to_addrs = None

    def __enter__(
        self,
    ):

        self.events.append(
            "enter"
        )

        return self

    def __exit__(
        self,
        *args,
    ):

        self.events.append(
            "exit"
        )

    def ehlo(
        self,
    ):

        self.events.append(
            "ehlo"
        )

    def starttls(
        self,
        context=None,
    ):

        self.events.append(
            "starttls"
        )

        self.tls_context = context

    def login(
        self,
        username,
        password,
    ):

        self.events.append(
            "login"
        )

        self.login_args = (
            username,
            password,
        )

        if self.error is not None:
            raise self.error

    def send_message(
        self,
        message,
        from_addr=None,
        to_addrs=None,
    ):

        self.events.append(
            "send_message"
        )

        if (
            self.error is not None
            and self.login_args is None
        ):

            raise self.error

        self.message = message
        self.from_addr = from_addr
        self.to_addrs = to_addrs


class Factory:

    def __init__(
        self,
        client,
    ):

        self.client = client
        self.calls = []

    def __call__(
        self,
        *args,
        **kwargs,
    ):

        self.calls.append(
            (
                args,
                kwargs,
            )
        )

        return self.client


def plan():

    return {
        "incident_id": "email-test",
        "event_type": (
            "incident_persisted"
        ),
        "severity": "HIGH",
        "risk_score": 82,
    }


def incident():

    return {
        "id": "email-test",
        "ip": "192.168.20.130",
        "alerts": [],
        "response_actions": [],
    }


def adapter(
    security="ssl",
    client=None,
    **kwargs,
):

    client = (
        client
        or FakeSMTP()
    )

    ssl_factory = Factory(
        client
    )

    plain_factory = Factory(
        client
    )

    tls_factory = (
        TLSContextFactory()
    )

    instance = (
        EmailNotificationAdapter(
            host=(
                "smtp.example.invalid"
            ),
            port=(
                465
                if security == "ssl"
                else 587
            ),
            security=security,
            timeout_seconds=5,
            sender=(
                "soc@example.invalid"
            ),
            recipient=(
                "analyst@example.invalid"
            ),
            smtp_ssl_factory=(
                ssl_factory
            ),
            smtp_factory=(
                plain_factory
            ),
            ssl_context_factory=(
                tls_factory
            ),
            **kwargs,
        )
    )

    return (
        instance,
        client,
        ssl_factory,
        plain_factory,
        tls_factory,
    )


def test_ssl_delivery_contract():

    (
        instance,
        client,
        ssl_factory,
        plain_factory,
        tls_factory,
    ) = adapter(
        security="ssl"
    )

    result = instance.send(
        plan(),
        incident(),
    )

    assert result == {
        "channel": "email",
        "status": "SUCCESS",
        "backend": "smtp_ssl",
    }

    assert len(
        ssl_factory.calls
    ) == 1

    assert (
        plain_factory.calls
        == []
    )

    args, kwargs = (
        ssl_factory.calls[0]
    )

    assert args == (
        "smtp.example.invalid",
        465,
    )

    assert kwargs[
        "timeout"
    ] == 5.0

    assert isinstance(
        kwargs[
            "context"
        ],
        FakeContext,
    )

    assert (
        client.from_addr
        == "soc@example.invalid"
    )

    assert client.to_addrs == [
        "analyst@example.invalid"
    ]


def test_starttls_delivery_contract():

    (
        instance,
        client,
        ssl_factory,
        plain_factory,
        tls_factory,
    ) = adapter(
        security="starttls"
    )

    result = instance.send(
        plan(),
        incident(),
    )

    assert result[
        "backend"
    ] == "smtp_starttls"

    assert (
        ssl_factory.calls
        == []
    )

    assert len(
        plain_factory.calls
    ) == 1

    assert client.events == [
        "enter",
        "ehlo",
        "starttls",
        "ehlo",
        "send_message",
        "exit",
    ]


def test_credentials_are_used_when_configured():

    (
        instance,
        client,
        *_,
    ) = adapter(
        username=(
            "soc-user"
        ),
        password=(
            "SUPER-SECRET"
        ),
    )

    instance.send(
        plan(),
        incident(),
    )

    assert client.login_args == (
        "soc-user",
        "SUPER-SECRET",
    )

    serialized = (
        client.message
        .as_string()
    )

    assert (
        "SUPER-SECRET"
        not in serialized
    )


def test_no_login_without_credentials():

    (
        instance,
        client,
        *_,
    ) = adapter()

    instance.send(
        plan(),
        incident(),
    )

    assert (
        client.login_args
        is None
    )


def test_invalid_security_mode_is_rejected():

    try:

        EmailNotificationAdapter(
            host=(
                "smtp.example.invalid"
            ),
            port=25,
            security="plain",
            timeout_seconds=5,
            sender=(
                "soc@example.invalid"
            ),
            recipient=(
                "analyst@example.invalid"
            ),
        )

    except ValueError as error:

        assert (
            "ssl or starttls"
            in str(error)
        )

    else:

        raise AssertionError(
            "plain SMTP accepted"
        )


def test_partial_credentials_are_rejected():

    try:

        EmailNotificationAdapter(
            host=(
                "smtp.example.invalid"
            ),
            port=465,
            security="ssl",
            timeout_seconds=5,
            sender=(
                "soc@example.invalid"
            ),
            recipient=(
                "analyst@example.invalid"
            ),
            username="soc-user",
            password="",
        )

    except ValueError as error:

        assert (
            "configured together"
            in str(error)
        )

    else:

        raise AssertionError(
            "partial credentials accepted"
        )


def test_header_injection_address_is_rejected():

    try:

        EmailNotificationAdapter(
            host=(
                "smtp.example.invalid"
            ),
            port=465,
            security="ssl",
            timeout_seconds=5,
            sender=(
                "soc@example.invalid\r\n"
                "Bcc: evil@example.invalid"
            ),
            recipient=(
                "analyst@example.invalid"
            ),
        )

    except ValueError:

        pass

    else:

        raise AssertionError(
            "header injection accepted"
        )


def test_authentication_error_is_sanitized():

    client = FakeSMTP(
        error=(
            smtplib
            .SMTPAuthenticationError(
                535,
                b"SECRET SERVER RESPONSE",
            )
        )
    )

    (
        instance,
        *_,
    ) = adapter(
        client=client,
        username="soc-user",
        password="SUPER-SECRET",
    )

    try:

        instance.send(
            plan(),
            incident(),
        )

    except RuntimeError as error:

        value = str(error)

        assert value == (
            "Email delivery failed: "
            "authentication error"
        )

        assert (
            "SECRET"
            not in value
        )

    else:

        raise AssertionError(
            "authentication error accepted"
        )


def test_tls_error_is_sanitized():

    client = FakeSMTP(
        error=ssl.SSLError(
            "PRIVATE TLS DETAIL"
        )
    )

    (
        instance,
        *_,
    ) = adapter(
        client=client,
    )

    try:

        instance.send(
            plan(),
            incident(),
        )

    except RuntimeError as error:

        assert str(error) == (
            "Email delivery failed: "
            "TLS error"
        )

    else:

        raise AssertionError(
            "TLS error accepted"
        )


def test_timeout_is_sanitized():

    client = FakeSMTP(
        error=TimeoutError(
            "PRIVATE TIMEOUT DETAIL"
        )
    )

    (
        instance,
        *_,
    ) = adapter(
        client=client,
    )

    try:

        instance.send(
            plan(),
            incident(),
        )

    except RuntimeError as error:

        assert str(error) == (
            "Email delivery failed: "
            "timeout"
        )

    else:

        raise AssertionError(
            "timeout accepted"
        )


def test_smtp_rejection_is_sanitized():

    client = FakeSMTP(
        error=(
            smtplib
            .SMTPDataError(
                554,
                b"PRIVATE SMTP RESPONSE",
            )
        )
    )

    (
        instance,
        *_,
    ) = adapter(
        client=client,
    )

    try:

        instance.send(
            plan(),
            incident(),
        )

    except RuntimeError as error:

        value = str(error)

        assert value == (
            "Email delivery failed: "
            "SMTP rejection"
        )

        assert (
            "PRIVATE"
            not in value
        )

    else:

        raise AssertionError(
            "SMTP rejection accepted"
        )
