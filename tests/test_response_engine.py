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


def test_protected_target_never_calls_backend():

    from engine.services.response_safety_policy import (
        ResponseSafetyPolicy,
    )

    backend = FakeFirewallBackend()

    policy = ResponseSafetyPolicy(
        protected_ips=[
            "192.168.20.128",
        ]
    )

    engine = ResponseEngine(
        response_mode="enforce",
        firewall_backend=backend,
        safety_policy=policy,
    )

    result = engine.execute(
        {
            "type": "BLOCK_IP",
            "target": "192.168.20.128",
            "status": "PENDING",
        }
    )

    assert (
        result["status"]
        == "PROTECTED"
    )

    assert (
        result["backend"]
        == "safety_policy"
    )

    assert (
        "protected"
        in result["reason"].lower()
    )

    assert backend.calls == []


def test_unprotected_target_reaches_backend():

    from engine.services.response_safety_policy import (
        ResponseSafetyPolicy,
    )

    backend = FakeFirewallBackend()

    policy = ResponseSafetyPolicy(
        protected_ips=[
            "192.168.20.128",
        ]
    )

    engine = ResponseEngine(
        response_mode="enforce",
        firewall_backend=backend,
        safety_policy=policy,
    )

    result = engine.execute(
        block_action()
    )

    assert (
        result["status"]
        == "SUCCESS"
    )

    assert backend.calls == [
        TARGET
    ]


def test_protected_target_is_protected_even_in_simulate():

    from engine.services.response_safety_policy import (
        ResponseSafetyPolicy,
    )

    policy = ResponseSafetyPolicy(
        protected_ips=[
            "192.168.20.128",
        ]
    )

    engine = ResponseEngine(
        response_mode="simulate",
        safety_policy=policy,
    )

    result = engine.execute(
        {
            "type": "BLOCK_IP",
            "target": "192.168.20.128",
            "status": "PENDING",
        }
    )

    assert (
        result["status"]
        == "PROTECTED"
    )

    assert (
        "192.168.20.128"
        not in engine.blocked_ips
    )


def test_execution_mode_simulated_block():

    engine = ResponseEngine(
        response_mode="simulate"
    )

    result = engine.execute(
        block_action()
    )

    assert result["status"] == "SIMULATED"
    assert result["execution_mode"] == "SIMULATED"
    assert result["backend"] == "memory"


def test_execution_mode_simulated_duplicate():

    engine = ResponseEngine(
        response_mode="simulate"
    )

    engine.execute(
        block_action()
    )

    result = engine.execute(
        block_action()
    )

    assert result["status"] == "SKIPPED"
    assert result["execution_mode"] == "SIMULATED"
    assert result["backend"] == "memory"


def test_execution_mode_enforced_block():

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

    assert result["status"] == "SUCCESS"
    assert result["execution_mode"] == "ENFORCED"
    assert result["backend"] == "windows_firewall"


def test_execution_mode_protected_block():

    from engine.services.response_safety_policy import (
        ResponseSafetyPolicy,
    )

    backend = FakeFirewallBackend()

    policy = ResponseSafetyPolicy(
        protected_ips=[
            "192.168.20.128",
        ]
    )

    engine = ResponseEngine(
        response_mode="enforce",
        firewall_backend=backend,
        safety_policy=policy,
    )

    result = engine.execute(
        {
            "type": "BLOCK_IP",
            "target": "192.168.20.128",
            "status": "PENDING",
        }
    )

    assert result["status"] == "PROTECTED"
    assert result["execution_mode"] == "PROTECTED"
    assert result["backend"] == "safety_policy"
    assert backend.calls == []


def test_notify_soc_is_local_execution():

    engine = ResponseEngine()

    result = engine.execute(
        {
            "type": "NOTIFY_SOC",
            "target": "SOC_TEAM",
            "status": "PENDING",
        }
    )

    assert result["status"] == "SUCCESS"
    assert result["execution_mode"] == "LOCAL"
    assert result["backend"] == "console"


@pytest.mark.parametrize(
    "action_type",
    [
        "ENABLE_MFA",
        "ISOLATE_HOST",
        "COLLECT_FORENSICS",
    ],
)
def test_placeholder_actions_are_explicitly_simulated(
    action_type
):

    engine = ResponseEngine()

    result = engine.execute(
        {
            "type": action_type,
            "target": TARGET,
            "status": "PENDING",
        }
    )

    assert result["status"] == "SUCCESS"
    assert result["execution_mode"] == "SIMULATED"
    assert result["backend"] == "simulation"


def test_failed_unknown_action_does_not_invent_execution_mode():

    engine = ResponseEngine()

    result = engine.execute(
        {
            "type": "UNKNOWN_ACTION",
            "target": TARGET,
            "status": "PENDING",
        }
    )

    assert result["status"] == "FAILED"
    assert "execution_mode" not in result


def test_failed_backend_does_not_claim_enforcement():

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

    assert result["status"] == "FAILED"
    assert "execution_mode" not in result
