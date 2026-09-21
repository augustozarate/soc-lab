import pytest

from engine.orchestration.pipelines.response_pipeline import (
    ResponsePipeline,
)


TARGET = "192.168.20.130"


class FakePolicy:

    def __init__(
        self,
        actions=None,
    ):

        self.actions = (
            actions
            if actions is not None
            else []
        )

    def evaluate(
        self,
        incident,
    ):

        return list(
            self.actions
        )


class FakeResponseEngine:

    def __init__(
        self,
        result,
    ):

        self.result = result
        self.calls = []

    def execute(
        self,
        action,
    ):

        self.calls.append(
            action
        )

        return dict(
            self.result
        )


class FakeLifecycle:

    def __init__(
        self,
        error=None,
    ):

        self.calls = []
        self.error = error

    def observe(
        self,
        result,
        incident,
    ):

        self.calls.append(
            (
                result,
                incident,
            )
        )

        if self.error:
            raise self.error

        return None


class FakeSOAR:

    def __init__(
        self,
        actions=None,
    ):

        self.actions = (
            actions
            if actions is not None
            else []
        )

    def evaluate(
        self,
        incident,
    ):

        return list(
            self.actions
        )


class FakeCaseManager:

    def __init__(self):

        self.calls = []

    def create_case(
        self,
        incident,
    ):

        self.calls.append(
            incident
        )

        return "case-1"


class FakeEventBus:

    def __init__(self):

        self.events = []

    def emit(
        self,
        event_type,
        payload,
    ):

        self.events.append(
            (
                event_type,
                payload,
            )
        )


def build_pipeline(
    result,
    policy_actions=None,
    soar_actions=None,
    lifecycle_error=None,
):

    lifecycle = FakeLifecycle(
        error=lifecycle_error
    )

    event_bus = FakeEventBus()

    pipeline = ResponsePipeline(
        response_policy_engine=FakePolicy(
            actions=(
                policy_actions
                if policy_actions is not None
                else [
                    {
                        "type": "BLOCK_IP",
                        "target": TARGET,
                        "status": "PENDING",
                    }
                ]
            )
        ),
        response_engine=FakeResponseEngine(
            result=result
        ),
        response_block_lifecycle=lifecycle,
        soar=FakeSOAR(
            actions=soar_actions
        ),
        case_manager=FakeCaseManager(),
        event_bus=event_bus,
    )

    return (
        pipeline,
        lifecycle,
        event_bus,
    )


def base_incident():

    return {
        "id": "incident-pipeline",
        "ip": TARGET,
        "risk_score": 10,
        "response_actions": [],
    }


def test_policy_result_is_observed_by_lifecycle():

    result = {
        "type": "BLOCK_IP",
        "target": TARGET,
        "status": "SUCCESS",
        "execution_mode": "ENFORCED",
        "backend": "windows_firewall",
        "backend_status": "CREATED",
    }

    pipeline, lifecycle, event_bus = (
        build_pipeline(
            result
        )
    )

    incident = base_incident()

    assert (
        pipeline.run({
            "incident": incident,
        })
        is True
    )

    assert len(lifecycle.calls) == 1

    observed_result, observed_incident = (
        lifecycle.calls[0]
    )

    assert observed_result == result

    assert (
        observed_incident
        is incident
    )

    assert (
        incident["response_actions"][0]
        == result
    )

    assert len(event_bus.events) == 1


def test_soar_actions_are_not_sent_to_lifecycle():

    result = {
        "type": "NOTIFY_SOC",
        "target": "SOC_TEAM",
        "status": "SUCCESS",
        "execution_mode": "LOCAL",
        "backend": "console",
    }

    soar_action = {
        "type": "BLOCK_IP",
        "target": TARGET,
        "status": "SIMULATED",
        "execution_mode": "SIMULATED",
        "backend": "simulation",
    }

    pipeline, lifecycle, _ = (
        build_pipeline(
            result=result,
            policy_actions=[
                {
                    "type": "NOTIFY_SOC",
                    "target": "SOC_TEAM",
                    "status": "PENDING",
                }
            ],
            soar_actions=[
                soar_action
            ],
        )
    )

    incident = base_incident()

    pipeline.run({
        "incident": incident,
    })

    assert len(lifecycle.calls) == 1

    assert (
        lifecycle.calls[0][0]["type"]
        == "NOTIFY_SOC"
    )

    assert (
        soar_action
        in incident["response_actions"]
    )


def test_lifecycle_failure_propagates():

    result = {
        "type": "BLOCK_IP",
        "target": TARGET,
        "status": "SUCCESS",
        "execution_mode": "ENFORCED",
        "backend": "windows_firewall",
        "backend_status": "CREATED",
    }

    pipeline, lifecycle, event_bus = (
        build_pipeline(
            result=result,
            lifecycle_error=RuntimeError(
                "durable write failed"
            ),
        )
    )

    incident = base_incident()

    with pytest.raises(
        RuntimeError,
        match="durable write failed",
    ):

        pipeline.run({
            "incident": incident,
        })

    assert len(lifecycle.calls) == 1

    assert result in (
        incident["response_actions"]
    )

    assert event_bus.events == []
