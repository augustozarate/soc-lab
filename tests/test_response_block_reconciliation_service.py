from datetime import (
    datetime,
    timezone,
)

import pytest

from engine.services.response_block_reconciliation_service import (
    ResponseBlockReconciliationService,
)


NOW = datetime(
    2026,
    9,
    21,
    18,
    0,
    tzinfo=timezone.utc,
)

TARGET = "192.168.20.130"
TARGET_2 = "192.168.20.131"


class FakeRepository:

    def __init__(
        self,
        rows=None,
    ):

        self.rows = list(
            rows or []
        )

        self.blocked_converged = []
        self.released = []
        self.failed = []

    def list_reconcilable(
        self,
        now,
    ):

        return list(
            self.rows
        )

    def mark_blocked_converged(
        self,
        target,
        now,
    ):

        self.blocked_converged.append(
            (
                target,
                now,
            )
        )

        return True

    def mark_released(
        self,
        target,
        now,
    ):

        self.released.append(
            (
                target,
                now,
            )
        )

        return True

    def mark_failed(
        self,
        target,
        error,
        now,
    ):

        self.failed.append(
            (
                target,
                str(error),
                now,
            )
        )

        return True


class FakeEngine:

    def __init__(
        self,
        blocked=None,
        results=None,
        errors=None,
    ):

        self.blocked_ips = set(
            blocked or []
        )

        self.results = (
            results or {}
        )

        self.errors = (
            errors or {}
        )

        self.calls = []

    def execute(
        self,
        action,
    ):

        self.calls.append(
            dict(action)
        )

        target = action["target"]

        if target in self.errors:
            raise self.errors[target]

        return dict(
            self.results[target]
        )


class FakeFirewall:

    def __init__(
        self,
        states=None,
        errors=None,
    ):

        self.states = (
            states or {}
        )

        self.errors = (
            errors or {}
        )

        self.calls = []

    def is_blocked(
        self,
        target,
    ):

        self.calls.append(
            target
        )

        if target in self.errors:
            raise self.errors[target]

        return self.states[
            target
        ]


def row(
    *,
    target=TARGET,
    desired_state,
    backend="memory",
    status="ACTIVE",
):

    return {
        "target": target,
        "desired_state": desired_state,
        "backend": backend,
        "status": status,
    }


def service(
    repository,
    engine,
    firewall=None,
):

    return ResponseBlockReconciliationService(
        repository=repository,
        response_engine=engine,
        firewall_backend=firewall,
        now_provider=lambda: NOW,
    )


def test_blocked_memory_already_converged():

    repository = FakeRepository([
        row(
            desired_state="BLOCKED",
        )
    ])

    engine = FakeEngine(
        blocked={
            TARGET
        }
    )

    outcomes = service(
        repository,
        engine,
    ).sweep()

    assert engine.calls == []

    assert (
        repository.blocked_converged
        == [
            (
                TARGET,
                NOW,
            )
        ]
    )

    assert (
        outcomes[0]["status"]
        == "CONVERGED"
    )


def test_blocked_memory_missing_is_repaired():

    repository = FakeRepository([
        row(
            desired_state="BLOCKED",
        )
    ])

    engine = FakeEngine(
        results={
            TARGET: {
                "type": "BLOCK_IP",
                "target": TARGET,
                "status": "SIMULATED",
                "backend": "memory",
                "execution_mode": "SIMULATED",
            }
        }
    )

    outcomes = service(
        repository,
        engine,
    ).sweep()

    assert (
        engine.calls[0]["type"]
        == "BLOCK_IP"
    )

    assert (
        outcomes[0]["status"]
        == "REPAIRED"
    )

    assert len(
        repository.blocked_converged
    ) == 1


@pytest.mark.parametrize(
    "query_result",
    [
        True,
        {
            "status": "EXISTS",
            "target": TARGET,
        },
    ],
)
def test_blocked_windows_already_converged(
    query_result,
):

    repository = FakeRepository([
        row(
            desired_state="BLOCKED",
            backend="windows_firewall",
        )
    ])

    firewall = FakeFirewall(
        states={
            TARGET: query_result
        }
    )

    engine = FakeEngine()

    outcomes = service(
        repository,
        engine,
        firewall,
    ).sweep()

    assert engine.calls == []

    assert (
        outcomes[0]["status"]
        == "CONVERGED"
    )


@pytest.mark.parametrize(
    "backend_status",
    [
        "CREATED",
        "EXISTS",
    ],
)
def test_blocked_windows_missing_is_repaired(
    backend_status,
):

    repository = FakeRepository([
        row(
            desired_state="BLOCKED",
            backend="windows_firewall",
        )
    ])

    firewall = FakeFirewall(
        states={
            TARGET: {
                "status": "MISSING",
                "target": TARGET,
            }
        }
    )

    engine = FakeEngine(
        results={
            TARGET: {
                "type": "BLOCK_IP",
                "target": TARGET,
                "status": "SUCCESS",
                "backend": "windows_firewall",
                "execution_mode": "ENFORCED",
                "backend_status": backend_status,
            }
        }
    )

    outcomes = service(
        repository,
        engine,
        firewall,
    ).sweep()

    assert (
        outcomes[0]["status"]
        == "REPAIRED"
    )

    assert (
        engine.calls[0]["type"]
        == "BLOCK_IP"
    )


def test_unblocked_memory_already_converged():

    repository = FakeRepository([
        row(
            desired_state="UNBLOCKED",
            status="FAILED",
        )
    ])

    engine = FakeEngine()

    outcomes = service(
        repository,
        engine,
    ).sweep()

    assert engine.calls == []

    assert (
        repository.released
        == [
            (
                TARGET,
                NOW,
            )
        ]
    )

    assert (
        outcomes[0]["status"]
        == "CONVERGED"
    )


def test_unblocked_memory_blocked_is_repaired():

    repository = FakeRepository([
        row(
            desired_state="UNBLOCKED",
            status="FAILED",
        )
    ])

    engine = FakeEngine(
        blocked={
            TARGET
        },
        results={
            TARGET: {
                "type": "UNBLOCK_IP",
                "target": TARGET,
                "status": "SIMULATED",
                "backend": "memory",
                "execution_mode": "SIMULATED",
            }
        },
    )

    outcomes = service(
        repository,
        engine,
    ).sweep()

    assert (
        engine.calls[0]["type"]
        == "UNBLOCK_IP"
    )

    assert (
        outcomes[0]["status"]
        == "REPAIRED"
    )

    assert len(
        repository.released
    ) == 1


def test_unblocked_windows_missing_converges():

    repository = FakeRepository([
        row(
            desired_state="UNBLOCKED",
            backend="windows_firewall",
            status="EXPIRED",
        )
    ])

    firewall = FakeFirewall(
        states={
            TARGET: {
                "status": "MISSING",
                "target": TARGET,
            }
        }
    )

    outcomes = service(
        repository,
        FakeEngine(),
        firewall,
    ).sweep()

    assert (
        outcomes[0]["status"]
        == "CONVERGED"
    )

    assert len(
        repository.released
    ) == 1


@pytest.mark.parametrize(
    "backend_status",
    [
        "REMOVED",
        "MISSING",
    ],
)
def test_unblocked_windows_rule_is_repaired(
    backend_status,
):

    repository = FakeRepository([
        row(
            desired_state="UNBLOCKED",
            backend="windows_firewall",
            status="FAILED",
        )
    ])

    firewall = FakeFirewall(
        states={
            TARGET: {
                "status": "EXISTS",
                "target": TARGET,
            }
        }
    )

    engine = FakeEngine(
        results={
            TARGET: {
                "type": "UNBLOCK_IP",
                "target": TARGET,
                "status": "SUCCESS",
                "backend": "windows_firewall",
                "execution_mode": "ENFORCED",
                "backend_status": backend_status,
            }
        }
    )

    outcomes = service(
        repository,
        engine,
        firewall,
    ).sweep()

    assert (
        outcomes[0]["status"]
        == "REPAIRED"
    )

    assert len(
        repository.released
    ) == 1


def test_block_repair_failure_is_persisted():

    repository = FakeRepository([
        row(
            desired_state="BLOCKED",
        )
    ])

    engine = FakeEngine(
        results={
            TARGET: {
                "type": "BLOCK_IP",
                "target": TARGET,
                "status": "FAILED",
                "error": "block failed",
            }
        }
    )

    outcomes = service(
        repository,
        engine,
    ).sweep()

    assert (
        outcomes[0]["status"]
        == "FAILED"
    )

    assert len(
        repository.failed
    ) == 1

    assert (
        "block failed"
        in repository.failed[0][1]
    )


def test_unblock_repair_failure_is_persisted():

    repository = FakeRepository([
        row(
            desired_state="UNBLOCKED",
            status="FAILED",
        )
    ])

    engine = FakeEngine(
        blocked={
            TARGET
        },
        results={
            TARGET: {
                "type": "UNBLOCK_IP",
                "target": TARGET,
                "status": "FAILED",
                "error": "unblock failed",
            }
        },
    )

    outcomes = service(
        repository,
        engine,
    ).sweep()

    assert (
        outcomes[0]["status"]
        == "FAILED"
    )

    assert len(
        repository.failed
    ) == 1

    assert (
        "unblock failed"
        in repository.failed[0][1]
    )


def test_query_failure_marks_failed():

    repository = FakeRepository([
        row(
            desired_state="BLOCKED",
            backend="windows_firewall",
        )
    ])

    firewall = FakeFirewall(
        errors={
            TARGET: RuntimeError(
                "query timeout"
            )
        }
    )

    outcomes = service(
        repository,
        FakeEngine(),
        firewall,
    ).sweep()

    assert (
        outcomes[0]["status"]
        == "FAILED"
    )

    assert len(
        repository.failed
    ) == 1

    assert (
        "query timeout"
        in repository.failed[0][1]
    )


def test_one_target_failure_does_not_stop_next():

    repository = FakeRepository([
        row(
            target=TARGET,
            desired_state="BLOCKED",
            backend="windows_firewall",
        ),
        row(
            target=TARGET_2,
            desired_state="UNBLOCKED",
            backend="memory",
            status="FAILED",
        ),
    ])

    firewall = FakeFirewall(
        errors={
            TARGET: RuntimeError(
                "query failed"
            )
        }
    )

    engine = FakeEngine()

    outcomes = service(
        repository,
        engine,
        firewall,
    ).sweep()

    assert [
        outcome["status"]
        for outcome in outcomes
    ] == [
        "FAILED",
        "CONVERGED",
    ]

    assert len(
        repository.failed
    ) == 1

    assert len(
        repository.released
    ) == 1


def test_unsupported_backend_marks_failed():

    repository = FakeRepository([
        row(
            desired_state="BLOCKED",
            backend="unknown",
        )
    ])

    outcomes = service(
        repository,
        FakeEngine(),
    ).sweep()

    assert (
        outcomes[0]["status"]
        == "FAILED"
    )

    assert (
        "Unsupported response block backend"
        in repository.failed[0][1]
    )


def test_naive_clock_rejected():

    reconciliation = (
        ResponseBlockReconciliationService(
            repository=FakeRepository(),
            response_engine=FakeEngine(),
            now_provider=lambda: datetime(
                2026,
                9,
                21,
                18,
                0,
            ),
        )
    )

    with pytest.raises(
        ValueError,
        match="timezone-aware",
    ):

        reconciliation.sweep()


def test_list_reconcilable_failure_propagates():

    class Repository:

        def list_reconcilable(
            self,
            now,
        ):

            raise RuntimeError(
                "database unavailable"
            )

    reconciliation = (
        ResponseBlockReconciliationService(
            repository=Repository(),
            response_engine=FakeEngine(),
            now_provider=lambda: NOW,
        )
    )

    with pytest.raises(
        RuntimeError,
        match="database unavailable",
    ):

        reconciliation.sweep()
