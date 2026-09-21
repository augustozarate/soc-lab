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

    # This test represents a same-mode
    # ENFORCED process using the exact same
    # firewall backend as the reconciler.
    engine.response_mode = "enforce"
    engine.firewall_backend = firewall


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

    # This test represents a same-mode
    # ENFORCED process using the exact same
    # firewall backend as the reconciler.
    engine.response_mode = "enforce"
    engine.firewall_backend = firewall


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


class AffinityFirewall:

    def __init__(
        self,
        blocked=None,
    ):

        self.blocked = set(
            blocked or []
        )

        self.block_calls = []
        self.unblock_calls = []
        self.query_calls = []

    def is_blocked(
        self,
        target,
    ):

        self.query_calls.append(
            target
        )

        return (
            target
            in self.blocked
        )

    def block(
        self,
        target,
    ):

        self.block_calls.append(
            target
        )

        existed = (
            target
            in self.blocked
        )

        self.blocked.add(
            target
        )

        return {
            "status": (
                "EXISTS"
                if existed
                else "CREATED"
            ),
            "target": target,
            "rule_name": (
                "SOC-LAB-BLOCK-"
                + target.replace(
                    ".",
                    "-",
                )
            ),
        }

    def unblock(
        self,
        target,
    ):

        self.unblock_calls.append(
            target
        )

        existed = (
            target
            in self.blocked
        )

        self.blocked.discard(
            target
        )

        return {
            "status": (
                "REMOVED"
                if existed
                else "MISSING"
            ),
            "target": target,
            "rule_name": (
                "SOC-LAB-BLOCK-"
                + target.replace(
                    ".",
                    "-",
                )
            ),
        }


def test_historic_windows_block_uses_windows_after_simulate_restart():

    from engine.services.response_engine import (
        ResponseEngine,
    )

    repository = FakeRepository([
        {
            "target": TARGET,
            "desired_state": "BLOCKED",
            "backend": "windows_firewall",
            "execution_mode": "ENFORCED",
            "status": "ACTIVE",
        }
    ])

    firewall = AffinityFirewall()

    engine = ResponseEngine(
        response_mode="simulate"
    )

    reconciliation = (
        ResponseBlockReconciliationService(
            repository=repository,
            response_engine=engine,
            firewall_backend=firewall,
            now_provider=lambda: NOW,
        )
    )

    outcomes = reconciliation.sweep()

    assert (
        outcomes[0]["status"]
        == "REPAIRED"
    )

    assert (
        outcomes[0]["action"]["backend"]
        == "windows_firewall"
    )

    assert (
        outcomes[0]["action"][
            "execution_mode"
        ]
        == "ENFORCED"
    )

    assert firewall.block_calls == [
        TARGET
    ]

    assert (
        TARGET
        not in engine.blocked_ips
    )


def test_historic_memory_block_never_escalates_after_enforce_restart():

    from engine.services.response_engine import (
        ResponseEngine,
    )

    firewall = AffinityFirewall()

    engine = ResponseEngine(
        response_mode="enforce",
        firewall_backend=firewall,
    )

    repository = FakeRepository([
        {
            "target": TARGET,
            "desired_state": "BLOCKED",
            "backend": "memory",
            "execution_mode": "SIMULATED",
            "status": "ACTIVE",
        }
    ])

    reconciliation = (
        ResponseBlockReconciliationService(
            repository=repository,
            response_engine=engine,
            firewall_backend=firewall,
            now_provider=lambda: NOW,
        )
    )

    outcomes = reconciliation.sweep()

    assert (
        outcomes[0]["status"]
        == "REPAIRED"
    )

    assert (
        outcomes[0]["action"]["backend"]
        == "memory"
    )

    assert (
        outcomes[0]["action"][
            "execution_mode"
        ]
        == "SIMULATED"
    )

    assert firewall.block_calls == []

    assert (
        TARGET
        in engine.blocked_ips
    )


def test_historic_windows_release_uses_windows_after_simulate_restart():

    from engine.services.response_engine import (
        ResponseEngine,
    )

    firewall = AffinityFirewall(
        blocked={
            TARGET
        }
    )

    engine = ResponseEngine(
        response_mode="simulate"
    )

    repository = FakeRepository([
        {
            "target": TARGET,
            "desired_state": "UNBLOCKED",
            "backend": "windows_firewall",
            "execution_mode": "ENFORCED",
            "status": "FAILED",
        }
    ])

    reconciliation = (
        ResponseBlockReconciliationService(
            repository=repository,
            response_engine=engine,
            firewall_backend=firewall,
            now_provider=lambda: NOW,
        )
    )

    outcomes = reconciliation.sweep()

    assert (
        outcomes[0]["status"]
        == "REPAIRED"
    )

    assert (
        outcomes[0]["action"]["backend"]
        == "windows_firewall"
    )

    assert (
        outcomes[0]["action"][
            "execution_mode"
        ]
        == "ENFORCED"
    )

    assert firewall.unblock_calls == [
        TARGET
    ]

    assert (
        TARGET
        not in firewall.blocked
    )

    assert len(
        repository.released
    ) == 1


def test_historic_memory_release_never_touches_windows_after_enforce_restart():

    from engine.services.response_engine import (
        ResponseEngine,
    )

    firewall = AffinityFirewall(
        blocked={
            TARGET
        }
    )

    engine = ResponseEngine(
        response_mode="enforce",
        firewall_backend=firewall,
    )

    engine.blocked_ips.add(
        TARGET
    )

    repository = FakeRepository([
        {
            "target": TARGET,
            "desired_state": "UNBLOCKED",
            "backend": "memory",
            "execution_mode": "SIMULATED",
            "status": "FAILED",
        }
    ])

    reconciliation = (
        ResponseBlockReconciliationService(
            repository=repository,
            response_engine=engine,
            firewall_backend=firewall,
            now_provider=lambda: NOW,
        )
    )

    outcomes = reconciliation.sweep()

    assert (
        outcomes[0]["status"]
        == "REPAIRED"
    )

    assert (
        outcomes[0]["action"]["backend"]
        == "memory"
    )

    assert firewall.unblock_calls == []

    assert (
        TARGET
        not in engine.blocked_ips
    )

    # The real firewall is deliberately
    # unrelated to a historical memory row.
    assert (
        TARGET
        in firewall.blocked
    )


def test_historic_windows_block_respects_current_safety_policy():

    from engine.services.response_engine import (
        ResponseEngine,
    )

    from engine.services.response_safety_policy import (
        ResponseSafetyPolicy,
    )

    firewall = AffinityFirewall()

    policy = ResponseSafetyPolicy(
        protected_ips=[
            TARGET
        ]
    )

    engine = ResponseEngine(
        response_mode="simulate",
        safety_policy=policy,
    )

    repository = FakeRepository([
        {
            "target": TARGET,
            "desired_state": "BLOCKED",
            "backend": "windows_firewall",
            "execution_mode": "ENFORCED",
            "status": "ACTIVE",
        }
    ])

    reconciliation = (
        ResponseBlockReconciliationService(
            repository=repository,
            response_engine=engine,
            firewall_backend=firewall,
            safety_policy=policy,
            now_provider=lambda: NOW,
        )
    )

    outcomes = reconciliation.sweep()

    assert (
        outcomes[0]["status"]
        == "FAILED"
    )

    assert firewall.block_calls == []

    assert (
        outcomes[0]["action"]["status"]
        == "PROTECTED"
    )

    assert (
        outcomes[0]["action"]["backend"]
        == "safety_policy"
    )

    assert len(
        repository.failed
    ) == 1


def test_historic_windows_unblock_allowed_for_currently_protected_target():

    from engine.services.response_engine import (
        ResponseEngine,
    )

    from engine.services.response_safety_policy import (
        ResponseSafetyPolicy,
    )

    firewall = AffinityFirewall(
        blocked={
            TARGET
        }
    )

    policy = ResponseSafetyPolicy(
        protected_ips=[
            TARGET
        ]
    )

    engine = ResponseEngine(
        response_mode="simulate",
        safety_policy=policy,
    )

    repository = FakeRepository([
        {
            "target": TARGET,
            "desired_state": "UNBLOCKED",
            "backend": "windows_firewall",
            "execution_mode": "ENFORCED",
            "status": "FAILED",
        }
    ])

    reconciliation = (
        ResponseBlockReconciliationService(
            repository=repository,
            response_engine=engine,
            firewall_backend=firewall,
            safety_policy=policy,
            now_provider=lambda: NOW,
        )
    )

    outcomes = reconciliation.sweep()

    assert (
        outcomes[0]["status"]
        == "REPAIRED"
    )

    assert firewall.unblock_calls == [
        TARGET
    ]

    assert (
        TARGET
        not in firewall.blocked
    )

    assert len(
        repository.released
    ) == 1


class RetryFirewall:

    def __init__(
        self,
        blocked=None,
        fail_block=False,
        fail_unblock=False,
    ):

        self.blocked = set(
            blocked or []
        )

        self.fail_block = fail_block
        self.fail_unblock = fail_unblock

        self.query_calls = []
        self.block_calls = []
        self.unblock_calls = []

    def is_blocked(
        self,
        target,
    ):

        self.query_calls.append(
            target
        )

        return (
            target
            in self.blocked
        )

    def block(
        self,
        target,
    ):

        self.block_calls.append(
            target
        )

        if self.fail_block:

            raise RuntimeError(
                "firewall unavailable"
            )

        existed = (
            target
            in self.blocked
        )

        self.blocked.add(
            target
        )

        return {
            "status": (
                "EXISTS"
                if existed
                else "CREATED"
            ),
            "target": target,
            "rule_name": (
                "SOC-LAB-BLOCK-"
                + target.replace(
                    ".",
                    "-",
                )
            ),
        }

    def unblock(
        self,
        target,
    ):

        self.unblock_calls.append(
            target
        )

        if self.fail_unblock:

            raise RuntimeError(
                "firewall unavailable"
            )

        existed = (
            target
            in self.blocked
        )

        self.blocked.discard(
            target
        )

        return {
            "status": (
                "REMOVED"
                if existed
                else "MISSING"
            ),
            "target": target,
            "rule_name": (
                "SOC-LAB-BLOCK-"
                + target.replace(
                    ".",
                    "-",
                )
            ),
        }


def _retry_repository():

    import tempfile

    from pathlib import Path

    from engine.storage.sqlite.database import (
        Database,
    )

    from engine.storage.sqlite.migrations import (
        MigrationRunner,
    )

    from engine.storage.repositories.response_block_repository import (
        ResponseBlockRepository,
    )

    directory = (
        tempfile.TemporaryDirectory()
    )

    db = Database(
        str(
            Path(directory.name)
            / "soc.db"
        )
    )

    MigrationRunner(
        db
    ).run()

    return (
        directory,
        ResponseBlockRepository(db),
    )


def test_failed_row_within_retry_cooldown_is_deferred_without_backend_access():

    from datetime import timedelta

    from engine.services.response_engine import (
        ResponseEngine,
    )

    directory, repository = (
        _retry_repository()
    )

    try:

        target = "192.168.20.250"

        repository.upsert_active(
            target=target,
            expires_at=(
                NOW
                + timedelta(
                    minutes=10
                )
            ),
            execution_mode="ENFORCED",
            backend="windows_firewall",
        )

        failed_at = (
            NOW
            - timedelta(
                seconds=10
            )
        )

        repository.mark_failed(
            target,
            "firewall unavailable",
            failed_at,
        )

        before = repository.get(
            target
        )

        firewall = RetryFirewall()

        engine = ResponseEngine(
            response_mode="simulate"
        )

        outcomes = (
            ResponseBlockReconciliationService(
                repository=repository,
                response_engine=engine,
                firewall_backend=firewall,
                retry_seconds=30,
                now_provider=lambda: NOW,
            )
            .sweep()
        )

        after = repository.get(
            target
        )

        assert outcomes == [
            {
                "target": target,
                "status": "DEFERRED",
                "reason": (
                    "Retry cooldown active"
                ),
            }
        ]

        assert firewall.query_calls == []
        assert firewall.block_calls == []
        assert firewall.unblock_calls == []

        assert (
            after["updated_at"]
            == before["updated_at"]
        )

        assert (
            after["last_error"]
            == before["last_error"]
        )

    finally:

        directory.cleanup()


def test_failed_row_retries_exactly_at_cooldown_boundary():

    from datetime import timedelta

    from engine.services.response_engine import (
        ResponseEngine,
    )

    directory, repository = (
        _retry_repository()
    )

    try:

        target = "192.168.20.251"

        repository.upsert_active(
            target=target,
            expires_at=(
                NOW
                + timedelta(
                    minutes=10
                )
            ),
            execution_mode="ENFORCED",
            backend="windows_firewall",
        )

        repository.mark_failed(
            target,
            "temporary failure",
            (
                NOW
                - timedelta(
                    seconds=30
                )
            ),
        )

        firewall = RetryFirewall()

        engine = ResponseEngine(
            response_mode="simulate"
        )

        outcomes = (
            ResponseBlockReconciliationService(
                repository=repository,
                response_engine=engine,
                firewall_backend=firewall,
                retry_seconds=30,
                now_provider=lambda: NOW,
            )
            .sweep()
        )

        assert (
            outcomes[0]["status"]
            == "REPAIRED"
        )

        assert firewall.query_calls == [
            target
        ]

        assert firewall.block_calls == [
            target
        ]

        final = repository.get(
            target
        )

        assert (
            final["status"]
            == "ACTIVE"
        )

        assert final["last_error"] is None

    finally:

        directory.cleanup()


def test_expired_row_bypasses_retry_cooldown_and_unblocks_immediately():

    from datetime import timedelta

    from engine.services.response_engine import (
        ResponseEngine,
    )

    directory, repository = (
        _retry_repository()
    )

    try:

        target = "192.168.20.252"

        repository.upsert_active(
            target=target,
            expires_at=(
                NOW
                - timedelta(
                    seconds=1
                )
            ),
            execution_mode="ENFORCED",
            backend="windows_firewall",
        )

        repository.mark_expired(
            target,
            (
                NOW
                - timedelta(
                    seconds=1
                )
            ),
        )

        firewall = RetryFirewall(
            blocked={
                target
            }
        )

        engine = ResponseEngine(
            response_mode="simulate"
        )

        outcomes = (
            ResponseBlockReconciliationService(
                repository=repository,
                response_engine=engine,
                firewall_backend=firewall,
                retry_seconds=30,
                now_provider=lambda: NOW,
            )
            .sweep()
        )

        assert (
            outcomes[0]["status"]
            == "REPAIRED"
        )

        assert firewall.query_calls == [
            target
        ]

        assert firewall.unblock_calls == [
            target
        ]

        final = repository.get(
            target
        )

        assert (
            final["status"]
            == "RELEASED"
        )

    finally:

        directory.cleanup()


def test_zero_retry_seconds_disables_cooldown():

    from datetime import timedelta

    from engine.services.response_engine import (
        ResponseEngine,
    )

    directory, repository = (
        _retry_repository()
    )

    try:

        target = "192.168.20.253"

        repository.upsert_active(
            target=target,
            expires_at=(
                NOW
                + timedelta(
                    minutes=10
                )
            ),
            execution_mode="ENFORCED",
            backend="windows_firewall",
        )

        repository.mark_failed(
            target,
            "temporary failure",
            NOW,
        )

        firewall = RetryFirewall()

        engine = ResponseEngine(
            response_mode="simulate"
        )

        outcomes = (
            ResponseBlockReconciliationService(
                repository=repository,
                response_engine=engine,
                firewall_backend=firewall,
                retry_seconds=0,
                now_provider=lambda: NOW,
            )
            .sweep()
        )

        assert (
            outcomes[0]["status"]
            == "REPAIRED"
        )

        assert firewall.query_calls == [
            target
        ]

        assert firewall.block_calls == [
            target
        ]

    finally:

        directory.cleanup()


def test_negative_retry_seconds_rejected():

    from engine.services.response_engine import (
        ResponseEngine,
    )

    import pytest

    with pytest.raises(
        ValueError,
        match="greater than or equal to 0",
    ):

        ResponseBlockReconciliationService(
            repository=object(),
            response_engine=(
                ResponseEngine(
                    response_mode="simulate"
                )
            ),
            retry_seconds=-1,
            now_provider=lambda: NOW,
        )
