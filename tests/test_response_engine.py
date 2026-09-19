import pytest

from engine.services.response_engine import (
    ResponseEngine,
)


TARGET = "192.168.20.130"

RULE_NAME = (
    "SOC-LAB-BLOCK-192-168-20-130"
)


class FakeFirewallBackend:

    def __init__(
        self,
        status="CREATED",
        error=None,
    ):

        self.status = status
        self.error = error
        self.calls = []

    def block(self, target):

        self.calls.append(
            target
        )

        if self.error:

            raise RuntimeError(
                self.error
            )

        return {
            "status": self.status,
            "rule_name": RULE_NAME,
            "target": target,
        }


def block_action():

    return {
        "type": "BLOCK_IP",
        "target": TARGET,
        "status": "PENDING",
        "reason": "test",
    }


def test_default_mode_is_simulate():

    engine = ResponseEngine()

    assert (
        engine.response_mode
        == "simulate"
    )

    assert (
        engine.firewall_backend
        is None
    )


def test_simulate_does_not_call_backend():

    backend = FakeFirewallBackend()

    engine = ResponseEngine(
        response_mode="simulate",
        firewall_backend=backend,
    )

    result = engine.execute(
        block_action()
    )

    assert (
        result["status"]
        == "SIMULATED"
    )

    assert (
        result["backend"]
        == "memory"
    )

    assert backend.calls == []

    assert TARGET in \
        engine.blocked_ips


def test_simulate_duplicate_is_skipped():

    engine = ResponseEngine(
        response_mode="simulate"
    )

    first = engine.execute(
        block_action()
    )

    second = engine.execute(
        block_action()
    )

    assert (
        first["status"]
        == "SIMULATED"
    )

    assert (
        second["status"]
        == "SKIPPED"
    )

    assert (
        second["backend"]
        == "memory"
    )


def test_enforce_calls_backend():

    backend = FakeFirewallBackend(
        status="CREATED"
    )

    engine = ResponseEngine(
        response_mode="enforce",
        firewall_backend=backend,
    )

    result = engine.execute(
        block_action()
    )

    assert backend.calls == [
        TARGET
    ]

    assert (
        result["status"]
        == "SUCCESS"
    )

    assert (
        result["backend"]
        == "windows_firewall"
    )

    assert (
        result["backend_status"]
        == "CREATED"
    )

    assert (
        result["rule_name"]
        == RULE_NAME
    )


def test_existing_rule_is_successful_enforcement():

    backend = FakeFirewallBackend(
        status="EXISTS"
    )

    engine = ResponseEngine(
        response_mode="enforce",
        firewall_backend=backend,
    )

    result = engine.execute(
        block_action()
    )

    assert (
        result["status"]
        == "SUCCESS"
    )

    assert (
        result["backend_status"]
        == "EXISTS"
    )


def test_backend_failure_is_not_success():

    backend = FakeFirewallBackend(
        error="Access is denied"
    )

    engine = ResponseEngine(
        response_mode="enforce",
        firewall_backend=backend,
    )

    result = engine.execute(
        block_action()
    )

    assert (
        result["status"]
        == "FAILED"
    )

    assert (
        "Access is denied"
        in result["error"]
    )


def test_enforce_without_backend_fails():

    engine = ResponseEngine(
        response_mode="enforce"
    )

    result = engine.execute(
        block_action()
    )

    assert (
        result["status"]
        == "FAILED"
    )

    assert (
        "not configured"
        in result["error"]
    )


def test_pending_handler_fails_closed():

    engine = ResponseEngine()

    def incomplete_handler(
        action
    ):
        return action

    engine.registry.register(
        "INCOMPLETE_TEST_ACTION",
        incomplete_handler,
    )

    result = engine.execute(
        {
            "type":
                "INCOMPLETE_TEST_ACTION",
            "status":
                "PENDING",
        }
    )

    assert (
        result["status"]
        == "FAILED"
    )

    assert (
        "without a final status"
        in result["error"]
    )


def test_invalid_response_mode_rejected():

    with pytest.raises(
        ValueError
    ):
        ResponseEngine(
            response_mode="invalid"
        )
