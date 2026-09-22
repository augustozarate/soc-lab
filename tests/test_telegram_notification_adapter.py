import requests

from engine.services.telegram_notification_adapter import (
    TelegramNotificationAdapter,
)


TOKEN = (
    "123456:"
    "FAKE-TELEGRAM-LAB-TOKEN"
)


class Response:

    def __init__(
        self,
        status_code=200,
        body=None,
        json_error=None,
    ):

        self.status_code = (
            status_code
        )

        self.body = (
            {
                "ok": True,
            }
            if body is None
            else body
        )

        self.json_error = (
            json_error
        )

    def json(
        self,
    ):

        if self.json_error is not None:

            raise self.json_error

        return self.body


class Recorder:

    def __init__(
        self,
        response=None,
        error=None,
    ):

        self.response = (
            response
            or Response()
        )

        self.error = error
        self.calls = []

    def __call__(
        self,
        url,
        **kwargs,
    ):

        self.calls.append(
            (
                url,
                kwargs,
            )
        )

        if self.error is not None:

            raise self.error

        return self.response


def plan():

    return {
        "incident_id": (
            "telegram-test"
        ),
        "severity": "HIGH",
        "risk_score": 81,
    }


def incident():

    return {
        "id": (
            "telegram-test"
        ),
        "ip": (
            "192.168.20.130"
        ),
        "alerts": [],
        "response_actions": [],
    }


def adapter(
    recorder,
    **kwargs,
):

    return TelegramNotificationAdapter(
        bot_token=TOKEN,
        chat_id=(
            "-1001234567890"
        ),
        timeout_seconds=5,
        post=recorder,
        **kwargs,
    )


def test_successful_https_request_contract():

    recorder = Recorder()

    instance = adapter(
        recorder
    )

    result = instance.send(
        plan(),
        incident(),
    )

    assert result == {
        "channel": "telegram",
        "status": "SUCCESS",
        "backend": (
            "telegram_bot_api"
        ),
        "http_status": 200,
    }

    assert len(
        recorder.calls
    ) == 1

    url, kwargs = (
        recorder.calls[0]
    )

    assert url == (
        "https://api.telegram.org/"
        f"bot{TOKEN}/sendMessage"
    )

    assert kwargs[
        "timeout"
    ] == 5.0

    assert (
        kwargs[
            "allow_redirects"
        ]
        is False
    )

    assert (
        kwargs[
            "verify"
        ]
        is True
    )

    assert kwargs[
        "json"
    ][
        "chat_id"
    ] == (
        "-1001234567890"
    )

    assert (
        TOKEN
        not in str(
            kwargs["json"]
        )
    )


def test_custom_ca_bundle_is_forwarded():

    recorder = Recorder()

    instance = adapter(
        recorder,
        ca_bundle=(
            "/tmp/telegram-ca.pem"
        ),
    )

    instance.send(
        plan(),
        incident(),
    )

    _, kwargs = (
        recorder.calls[0]
    )

    assert kwargs[
        "verify"
    ] == (
        "/tmp/telegram-ca.pem"
    )


def test_non_https_base_url_is_rejected():

    try:

        TelegramNotificationAdapter(
            bot_token=TOKEN,
            chat_id="1",
            api_base_url=(
                "http://localhost"
            ),
        )

    except ValueError as error:

        assert (
            "must use HTTPS"
            in str(error)
        )

    else:

        raise AssertionError(
            "HTTP Telegram base URL accepted"
        )


def test_embedded_base_url_credentials_rejected():

    try:

        TelegramNotificationAdapter(
            bot_token=TOKEN,
            chat_id="1",
            api_base_url=(
                "https://user:secret@"
                "example.invalid"
            ),
        )

    except ValueError:

        pass

    else:

        raise AssertionError(
            "embedded credentials accepted"
        )


def test_token_header_injection_rejected():

    try:

        TelegramNotificationAdapter(
            bot_token=(
                "token\r\n"
                "X-Test: evil"
            ),
            chat_id="1",
        )

    except ValueError:

        pass

    else:

        raise AssertionError(
            "invalid token accepted"
        )


def test_chat_id_header_injection_rejected():

    try:

        TelegramNotificationAdapter(
            bot_token=TOKEN,
            chat_id=(
                "123\r\n"
                "evil"
            ),
        )

    except ValueError:

        pass

    else:

        raise AssertionError(
            "invalid chat_id accepted"
        )


def test_authentication_error_is_sanitized():

    recorder = Recorder(
        response=Response(
            status_code=401,
            body={
                "ok": False,
                "description": (
                    TOKEN
                ),
            },
        )
    )

    try:

        adapter(
            recorder
        ).send(
            plan(),
            incident(),
        )

    except RuntimeError as error:

        value = str(
            error
        )

        assert value == (
            "Telegram delivery failed: "
            "authentication error"
        )

        assert TOKEN not in value

    else:

        raise AssertionError(
            "401 unexpectedly succeeded"
        )


def test_rate_limit_error_is_sanitized():

    recorder = Recorder(
        response=Response(
            status_code=429,
            body={
                "ok": False,
                "description": (
                    "PRIVATE PROVIDER TEXT"
                ),
                "parameters": {
                    "retry_after": 42,
                },
            },
        )
    )

    try:

        adapter(
            recorder
        ).send(
            plan(),
            incident(),
        )

    except RuntimeError as error:

        value = str(
            error
        )

        assert value == (
            "Telegram delivery failed: "
            "rate limited"
        )

        assert (
            "PRIVATE"
            not in value
        )

    else:

        raise AssertionError(
            "429 unexpectedly succeeded"
        )


def test_server_error_is_sanitized():

    recorder = Recorder(
        response=Response(
            status_code=500,
            body={
                "ok": False,
                "description": TOKEN,
            },
        )
    )

    try:

        adapter(
            recorder
        ).send(
            plan(),
            incident(),
        )

    except RuntimeError as error:

        assert str(
            error
        ) == (
            "Telegram delivery failed: "
            "API rejection"
        )

    else:

        raise AssertionError(
            "500 unexpectedly succeeded"
        )


def test_ok_false_is_rejected():

    recorder = Recorder(
        response=Response(
            status_code=200,
            body={
                "ok": False,
                "description": TOKEN,
            },
        )
    )

    try:

        adapter(
            recorder
        ).send(
            plan(),
            incident(),
        )

    except RuntimeError as error:

        value = str(
            error
        )

        assert value == (
            "Telegram delivery failed: "
            "API rejection"
        )

        assert TOKEN not in value

    else:

        raise AssertionError(
            "ok=false unexpectedly succeeded"
        )


def test_invalid_json_is_rejected():

    recorder = Recorder(
        response=Response(
            json_error=ValueError(
                TOKEN
            )
        )
    )

    try:

        adapter(
            recorder
        ).send(
            plan(),
            incident(),
        )

    except RuntimeError as error:

        value = str(
            error
        )

        assert value == (
            "Telegram delivery failed: "
            "API rejection"
        )

        assert TOKEN not in value

    else:

        raise AssertionError(
            "invalid JSON unexpectedly succeeded"
        )


def test_timeout_is_sanitized():

    recorder = Recorder(
        error=(
            requests
            .exceptions
            .Timeout(
                (
                    "https://api.telegram.org/"
                    f"bot{TOKEN}/sendMessage"
                )
            )
        )
    )

    try:

        adapter(
            recorder
        ).send(
            plan(),
            incident(),
        )

    except RuntimeError as error:

        value = str(
            error
        )

        assert value == (
            "Telegram delivery failed: "
            "timeout"
        )

        assert TOKEN not in value

    else:

        raise AssertionError(
            "timeout unexpectedly succeeded"
        )


def test_tls_error_is_sanitized():

    recorder = Recorder(
        error=(
            requests
            .exceptions
            .SSLError(
                TOKEN
            )
        )
    )

    try:

        adapter(
            recorder
        ).send(
            plan(),
            incident(),
        )

    except RuntimeError as error:

        assert str(
            error
        ) == (
            "Telegram delivery failed: "
            "TLS error"
        )

    else:

        raise AssertionError(
            "TLS failure unexpectedly succeeded"
        )


def test_connection_error_is_sanitized():

    recorder = Recorder(
        error=(
            requests
            .exceptions
            .ConnectionError(
                TOKEN
            )
        )
    )

    try:

        adapter(
            recorder
        ).send(
            plan(),
            incident(),
        )

    except RuntimeError as error:

        assert str(
            error
        ) == (
            "Telegram delivery failed: "
            "connection error"
        )

    else:

        raise AssertionError(
            "connection failure "
            "unexpectedly succeeded"
        )


def test_message_length_configuration_applies():

    recorder = Recorder()

    instance = TelegramNotificationAdapter(
        bot_token=TOKEN,
        chat_id="1",
        max_message_chars=100,
        post=recorder,
    )

    instance.send(
        {
            "incident_id": (
                "X" * 1000
            ),
            "severity": "HIGH",
            "risk_score": 80,
        },
        {
            "alerts": [],
            "response_actions": [],
        },
    )

    _, kwargs = (
        recorder.calls[0]
    )

    assert len(
        kwargs[
            "json"
        ][
            "text"
        ]
    ) <= 100
