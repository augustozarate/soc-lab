import asyncio
import ssl

import aiohttp

from engine.compat.threema_python import (
    install_threema_python_compat,
)

install_threema_python_compat()

from threema.gateway.exception import (
    GatewayError,
    MessageServerError,
)

from engine.services.threema_notification_adapter import (
    ThreemaNotificationAdapter,
)


class Builder:

    calls = []

    def build(
        self,
        plan,
        incident,
    ):

        self.__class__.calls.append(
            (
                plan,
                incident,
            )
        )

        return (
            "[SOC][HIGH]\n"
            "Incident: adapter-test"
        )


class Connection:

    def __init__(
        self,
    ):

        self.close_count = 0

    async def close(
        self,
    ):

        self.close_count += 1


class Factory:

    def __init__(
        self,
        connection=None,
        error=None,
    ):

        self.connection = (
            connection
            or Connection()
        )

        self.error = error
        self.build_count = 0

    def build(
        self,
    ):

        self.build_count += 1

        if self.error is not None:

            raise self.error

        return self.connection


class Client:

    instances = []
    error = None
    result = "MESSAGE-ID"

    def __init__(
        self,
        connection,
        recipient_id,
        recipient_public_key,
    ):

        self.connection = connection
        self.recipient_id = recipient_id
        self.recipient_public_key = (
            recipient_public_key
        )

        self.send_count = 0

        self.__class__.instances.append(
            self
        )

    async def send_text(
        self,
        text,
    ):

        self.send_count += 1
        self.text = text

        if self.__class__.error is not None:

            raise self.__class__.error

        return self.__class__.result


def reset():

    Builder.calls.clear()
    Client.instances.clear()
    Client.error = None
    Client.result = "MESSAGE-ID"


def adapter(
    factory=None,
):

    return ThreemaNotificationAdapter(
        recipient_id="ABCD1234",
        recipient_public_key=(
            "public:"
            + ("11" * 32)
        ),
        message_builder=Builder(),
        connection_factory=(
            factory
            or Factory()
        ),
        client_class=Client,
    )


def sample():

    return (
        {
            "incident_id": "incident-1",
            "severity": "HIGH",
            "risk_score": 90,
        },
        {
            "id": "incident-1",
        },
    )


def send(
    instance,
):

    plan, incident = sample()

    return instance.send(
        plan,
        incident,
    )


def test_success_is_structured_and_single_attempt():

    reset()

    connection = Connection()
    factory = Factory(
        connection=connection
    )

    result = send(
        adapter(
            factory
        )
    )

    assert result == {
        "channel": "threema",
        "status": "SUCCESS",
        "backend": (
            "threema_gateway"
        ),
    }

    assert factory.build_count == 1

    assert len(
        Client.instances
    ) == 1

    client = Client.instances[0]

    assert client.send_count == 1

    assert (
        client.connection
        is connection
    )

    assert (
        client.recipient_id
        == "ABCD1234"
    )

    assert (
        client.text
        == (
            "[SOC][HIGH]\n"
            "Incident: adapter-test"
        )
    )

    assert connection.close_count == 1

    assert len(
        Builder.calls
    ) == 1


def test_429_returns_rate_limited_without_retry_after():

    reset()

    connection = Connection()
    factory = Factory(
        connection=connection
    )

    Client.error = (
        MessageServerError(
            429
        )
    )

    result = send(
        adapter(
            factory
        )
    )

    assert result == {
        "channel": "threema",
        "status": "RATE_LIMITED",
        "backend": (
            "threema_gateway"
        ),
        "http_status": 429,
        "reason": (
            "Threema delivery "
            "rate limited"
        ),
    }

    assert (
        "retry_after_seconds"
        not in result
    )

    assert (
        Client.instances[0]
        .send_count
        == 1
    )

    assert connection.close_count == 1


def test_400_is_sanitized():

    reset()

    Client.error = (
        MessageServerError(
            400
        )
    )

    try:

        send(
            adapter()
        )

    except RuntimeError as error:

        assert str(
            error
        ) == (
            "Threema delivery failed: "
            "invalid request"
        )

    else:

        raise AssertionError(
            "400 did not fail"
        )


def test_401_is_sanitized():

    reset()

    Client.error = (
        MessageServerError(
            401
        )
    )

    try:

        send(
            adapter()
        )

    except RuntimeError as error:

        assert str(
            error
        ) == (
            "Threema delivery failed: "
            "authentication error"
        )

    else:

        raise AssertionError(
            "401 did not fail"
        )


def test_402_is_sanitized():

    reset()

    Client.error = (
        MessageServerError(
            402
        )
    )

    try:

        send(
            adapter()
        )

    except RuntimeError as error:

        assert str(
            error
        ) == (
            "Threema delivery failed: "
            "credits exhausted"
        )

    else:

        raise AssertionError(
            "402 did not fail"
        )


def test_413_is_sanitized():

    reset()

    Client.error = (
        MessageServerError(
            413
        )
    )

    try:

        send(
            adapter()
        )

    except RuntimeError as error:

        assert str(
            error
        ) == (
            "Threema delivery failed: "
            "payload too large"
        )

    else:

        raise AssertionError(
            "413 did not fail"
        )


def test_500_is_sanitized():

    reset()

    Client.error = (
        MessageServerError(
            500
        )
    )

    try:

        send(
            adapter()
        )

    except RuntimeError as error:

        assert str(
            error
        ) == (
            "Threema delivery failed: "
            "provider unavailable"
        )

    else:

        raise AssertionError(
            "500 did not fail"
        )


def test_timeout_is_sanitized():

    reset()

    Client.error = (
        asyncio.TimeoutError(
            "PRIVATE TIMEOUT DATA"
        )
    )

    try:

        send(
            adapter()
        )

    except RuntimeError as error:

        message = str(
            error
        )

        assert message == (
            "Threema delivery failed: "
            "timeout"
        )

        assert (
            "PRIVATE TIMEOUT DATA"
            not in message
        )

    else:

        raise AssertionError(
            "Timeout did not fail"
        )


def test_tls_error_is_sanitized():

    reset()

    Client.error = ssl.SSLError(
        "PRIVATE TLS DATA"
    )

    try:

        send(
            adapter()
        )

    except RuntimeError as error:

        message = str(
            error
        )

        assert message == (
            "Threema delivery failed: "
            "TLS error"
        )

        assert (
            "PRIVATE TLS DATA"
            not in message
        )

    else:

        raise AssertionError(
            "TLS error did not fail"
        )


def test_connection_error_is_sanitized():

    reset()

    Client.error = (
        aiohttp.ClientConnectionError(
            "PRIVATE CONNECTION DATA"
        )
    )

    try:

        send(
            adapter()
        )

    except RuntimeError as error:

        message = str(
            error
        )

        assert message == (
            "Threema delivery failed: "
            "connection error"
        )

        assert (
            "PRIVATE CONNECTION DATA"
            not in message
        )

    else:

        raise AssertionError(
            "Connection error did not fail"
        )


def test_sdk_error_is_sanitized():

    reset()

    Client.error = GatewayError(
        "PRIVATE SDK DATA"
    )

    try:

        send(
            adapter()
        )

    except RuntimeError as error:

        message = str(
            error
        )

        assert message == (
            "Threema delivery failed: "
            "SDK error"
        )

        assert (
            "PRIVATE SDK DATA"
            not in message
        )

    else:

        raise AssertionError(
            "SDK error did not fail"
        )


def test_connection_is_closed_when_send_fails():

    reset()

    connection = Connection()
    factory = Factory(
        connection=connection
    )

    Client.error = GatewayError(
        "PRIVATE"
    )

    try:

        send(
            adapter(
                factory
            )
        )

    except RuntimeError:

        pass

    else:

        raise AssertionError(
            "Provider error did not fail"
        )

    assert connection.close_count == 1

    assert (
        Client.instances[0]
        .send_count
        == 1
    )


def test_active_event_loop_fails_closed():

    reset()

    instance = adapter()

    async def proof():

        try:

            send(
                instance
            )

        except RuntimeError as error:

            assert str(
                error
            ) == (
                "Threema delivery failed: "
                "async context conflict"
            )

        else:

            raise AssertionError(
                "Active loop was accepted"
            )

    asyncio.run(
        proof()
    )
