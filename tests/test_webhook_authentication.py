import requests

from engine.services.webhook_notification_adapter import (
    WebhookNotificationAdapter,
)


class Response:

    status_code = 204


class Recorder:

    def __init__(
        self,
        error=None,
    ):

        self.calls = []
        self.error = error

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

        return Response()


def plan():

    return {
        "incident_id": "auth-test",
        "event_type": (
            "incident_persisted"
        ),
        "severity": "CRITICAL",
        "risk_score": 98,
    }


def incident():

    return {
        "id": "auth-test",
        "ip": "192.168.20.130",
        "alerts": [],
        "response_actions": [],
    }


def test_bearer_auth_header_is_added():

    recorder = Recorder()

    adapter = WebhookNotificationAdapter(
        url=(
            "https://example.invalid/hook"
        ),
        auth_token="soc-secret",
        post=recorder,
    )

    result = adapter.send(
        plan(),
        incident(),
    )

    assert (
        result["status"]
        == "SUCCESS"
    )

    _, kwargs = recorder.calls[0]

    assert kwargs[
        "headers"
    ][
        "Authorization"
    ] == (
        "Bearer soc-secret"
    )


def test_no_auth_header_without_token():

    recorder = Recorder()

    adapter = WebhookNotificationAdapter(
        url=(
            "https://example.invalid/hook"
        ),
        post=recorder,
    )

    adapter.send(
        plan(),
        incident(),
    )

    _, kwargs = recorder.calls[0]

    assert (
        "Authorization"
        not in kwargs[
            "headers"
        ]
    )


def test_token_never_enters_payload():

    recorder = Recorder()

    adapter = WebhookNotificationAdapter(
        url=(
            "https://example.invalid/hook"
        ),
        auth_token=(
            "TOP-SECRET-TOKEN"
        ),
        post=recorder,
    )

    adapter.send(
        plan(),
        incident(),
    )

    _, kwargs = recorder.calls[0]

    payload_text = str(
        kwargs["json"]
    )

    assert (
        "TOP-SECRET-TOKEN"
        not in payload_text
    )


def test_header_injection_token_is_rejected():

    try:

        WebhookNotificationAdapter(
            url=(
                "https://example.invalid/hook"
            ),
            auth_token=(
                "valid\r\n"
                "X-Evil: yes"
            ),
        )

    except ValueError as error:

        assert (
            "invalid characters"
            in str(error)
        )

    else:

        raise AssertionError(
            "header injection token accepted"
        )


def test_custom_ca_bundle_is_forwarded():

    recorder = Recorder()

    adapter = WebhookNotificationAdapter(
        url=(
            "https://example.invalid/hook"
        ),
        ca_bundle=(
            "/tmp/test-ca.pem"
        ),
        post=recorder,
    )

    adapter.send(
        plan(),
        incident(),
    )

    _, kwargs = recorder.calls[0]

    assert kwargs[
        "verify"
    ] == (
        "/tmp/test-ca.pem"
    )


def test_transport_error_does_not_leak_token():

    secret = (
        "SUPER-SECRET-WEBHOOK-TOKEN"
    )

    recorder = Recorder(
        error=(
            requests
            .exceptions
            .Timeout(
                secret
            )
        )
    )

    adapter = WebhookNotificationAdapter(
        url=(
            "https://example.invalid/hook"
        ),
        auth_token=secret,
        post=recorder,
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
            "timeout"
        )

        assert secret not in value

    else:

        raise AssertionError(
            "timeout unexpectedly succeeded"
        )
