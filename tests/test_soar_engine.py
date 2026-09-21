from engine.services.soar_engine import (
    SOAREngine,
)


TARGET = "192.168.20.130"


def critical_incident(
    response_actions=None,
):

    return {
        "id": "incident-critical",
        "ip": TARGET,
        "severity": "CRITICAL",
        "risk_score": 95,
        "response_actions": (
            []
            if response_actions is None
            else response_actions
        ),
    }


def test_critical_incident_generates_explicit_simulated_block():

    engine = SOAREngine()

    actions = engine.evaluate(
        critical_incident()
    )

    assert len(actions) == 1

    action = actions[0]

    assert action == {
        "type": "BLOCK_IP",
        "target": TARGET,
        "status": "SIMULATED",
        "execution_mode": "SIMULATED",
        "backend": "simulation",
    }


def test_high_incident_generates_no_soar_block():

    engine = SOAREngine()

    actions = engine.evaluate({
        "id": "incident-high",
        "ip": TARGET,
        "severity": "HIGH",
        "risk_score": 85,
        "response_actions": [],
    })

    assert actions == []


def test_existing_block_action_prevents_duplicate_soar_block():

    engine = SOAREngine()

    actions = engine.evaluate(
        critical_incident(
            response_actions=[
                {
                    "type": "BLOCK_IP",
                    "target": TARGET,
                    "status": "SUCCESS",
                    "execution_mode": "ENFORCED",
                    "backend": "windows_firewall",
                }
            ]
        )
    )

    assert actions == []


def test_soar_simulation_does_not_claim_memory_backend():

    engine = SOAREngine()

    action = engine.evaluate(
        critical_incident()
    )[0]

    assert (
        action["backend"]
        == "simulation"
    )

    assert (
        action["execution_mode"]
        == "SIMULATED"
    )

    assert (
        action["backend"]
        != "memory"
    )


def test_soar_simulation_does_not_claim_enforcement():

    engine = SOAREngine()

    action = engine.evaluate(
        critical_incident()
    )[0]

    assert (
        action["status"]
        == "SIMULATED"
    )

    assert (
        action["execution_mode"]
        != "ENFORCED"
    )

    assert (
        action["backend"]
        != "windows_firewall"
    )
