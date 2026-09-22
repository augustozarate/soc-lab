import requests

from engine.services.webhook_notification_adapter import (
    WebhookNotificationAdapter,
)


class Response:

    def __init__(
        self,
        status_code,
    ):

        self.status_code = (
            status_code
        )


class Recorder:

    def __init__(
        self,
        response=None,
        error=None,
    ):

        self.response = (
            response
            or Response(
                204
            )
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
        "incident_id": "inc-webhook",
        "event_type": (
            "incident_persisted"
        ),
        "severity": "CRITICAL",
        "risk_score": 99.0,
    }


def incident():

    return {
        "id": "inc-webhook",
        "ip": "192.168.20.130",
        "alerts": [],
        "response_actions": [],
    }


def test_successful_https_post_contract():

    recorder = Recorder(
        Response(
            204
        )
    )

    adapter = (
        WebhookNotificationAdapter(
            url=(
                "https://example.invalid/"
                "soc-hook"
            ),
            timeout_seconds=3,
            post=recorder,
        )
    )

    result = adapter.send(
        plan(),
        incident(),
    )

    assert result == {
        "channel": "webhook",
        "status": "SUCCESS",
        "backend": "https",
        "http_status": 204,
    }

    assert len(
        recorder.calls
    ) == 1

    url, kwargs = (
        recorder.calls[0]
    )

    assert url == (
        "https://example.invalid/"
        "soc-hook"
    )

    assert kwargs[
        "timeout"
    ] == 3.0

    assert kwargs[
        "allow_redirects"
    ] is False

    assert kwargs[
        "verify"
    ] is True

    assert kwargs[
        "headers"
    ] == {
        "Content-Type": (
            "application/json"
        )
    }

    assert kwargs[
        "json"
    ][
        "incident_id"
    ] == "inc-webhook"


def test_http_url_is_rejected():

    try:

        WebhookNotificationAdapter(
            url=(
                "http://example.invalid/"
                "hook"
            )
        )

    except ValueError as error:

        assert (
            "HTTPS"
            in str(error)
        )

    else:

        raise AssertionError(
            "HTTP webhook accepted"
        )


def test_embedded_credentials_are_rejected():

    try:

        WebhookNotificationAdapter(
            url=(
                "https://user:secret@"
                "example.invalid/hook"
            )
        )

    except ValueError as error:

        assert (
            "embedded credentials"
            in str(error)
        )

    else:

        raise AssertionError(
            "embedded credentials accepted"
        )


def test_redirect_is_not_success():

    adapter = (
        WebhookNotificationAdapter(
            url=(
                "https://example.invalid/"
                "hook"
            ),
            post=Recorder(
                Response(
                    302
                )
            ),
        )
    )

    try:

        adapter.send(
            plan(),
            incident(),
        )

    except RuntimeError as error:

        assert str(error) == (
            "Webhook request failed: "
            "HTTP 302"
        )

    else:

        raise AssertionError(
            "redirect treated as success"
        )


def test_server_error_is_sanitized():

    adapter = (
        WebhookNotificationAdapter(
            url=(
                "https://example.invalid/"
                "hook?token=secret"
            ),
            post=Recorder(
                Response(
                    503
                )
            ),
        )
    )

    try:

        adapter.send(
            plan(),
            incident(),
        )

    except RuntimeError as error:

        value = str(error)

        assert value == (
            "Webhook request failed: "
            "HTTP 503"
        )

        assert (
            "secret"
            not in value
        )

        assert (
            "example.invalid"
            not in value
        )

    else:

        raise AssertionError(
            "503 treated as success"
        )


def test_timeout_is_sanitized():

    adapter = (
        WebhookNotificationAdapter(
            url=(
                "https://example.invalid/"
                "hook"
            ),
            post=Recorder(
                error=(
                    requests
                    .exceptions
                    .Timeout(
                        "secret URL data"
                    )
                )
            ),
        )
    )

    try:

        adapter.send(
            plan(),
            incident(),
        )

    except RuntimeError as error:

        assert str(error) == (
            "Webhook request failed: "
            "timeout"
        )

    else:

        raise AssertionError(
            "timeout accepted"
        )


def test_tls_error_is_sanitized():

    adapter = (
        WebhookNotificationAdapter(
            url=(
                "https://example.invalid/"
                "hook"
            ),
            post=Recorder(
                error=(
                    requests
                    .exceptions
                    .SSLError(
                        "certificate details"
                    )
                )
            ),
        )
    )

    try:

        adapter.send(
            plan(),
            incident(),
        )

    except RuntimeError as error:

        assert str(error) == (
            "Webhook request failed: "
            "TLS error"
        )

    else:

        raise AssertionError(
            "TLS error accepted"
        )


def test_payload_size_is_bounded():

    class Builder:

        def build(
            self,
            plan,
            incident,
        ):

            return {
                "value": (
                    "X"
                    * 4096
                )
            }

    recorder = Recorder()

    adapter = (
        WebhookNotificationAdapter(
            url=(
                "https://example.invalid/"
                "hook"
            ),
            max_payload_bytes=128,
            payload_builder=Builder(),
            post=recorder,
        )
    )

    try:

        adapter.send(
            plan(),
            incident(),
        )

    except RuntimeError as error:

        assert str(error) == (
            "Webhook request failed: "
            "payload too large"
        )

    else:

        raise AssertionError(
            "oversized payload accepted"
        )

    assert recorder.calls == []


def test_invalid_timeout_is_rejected():

    try:

        WebhookNotificationAdapter(
            url=(
                "https://example.invalid/"
                "hook"
            ),
            timeout_seconds=0,
        )

    except ValueError:

        pass

    else:

        raise AssertionError(
            "zero timeout accepted"
        )
