from datetime import (
    datetime,
    timedelta,
    timezone,
)

import tempfile

from pathlib import Path

import pytest

from engine.services.response_block_expiration_service import (
    ResponseBlockExpirationService,
)

from engine.services.response_block_reconciliation_service import (
    ResponseBlockReconciliationService,
)

from engine.services.response_engine import (
    ResponseEngine,
)

from engine.storage.repositories.response_block_repository import (
    ResponseBlockRepository,
)

from engine.storage.sqlite.database import (
    Database,
)

from engine.storage.sqlite.migrations import (
    MigrationRunner,
)


TARGET = "192.168.20.130"
TARGET_2 = "192.168.20.131"

NOW = datetime(
    2026,
    9,
    21,
    15,
    0,
    tzinfo=timezone.utc,
)


class FakeRepository:

    def __init__(
        self,
        expired=None,
    ):

        self.expired = list(
            expired or []
        )

        self.expired_calls = []
        self.mark_expired_result = {}
        self.mark_expired_errors = {}

    def list_expired(
        self,
        now,
    ):

        return list(
            self.expired
        )

    def mark_expired(
        self,
        target,
        now,
    ):

        self.expired_calls.append(
            (
                target,
                now,
            )
        )

        if target in self.mark_expired_errors:

            raise self.mark_expired_errors[
                target
            ]

        return self.mark_expired_result.get(
            target,
            True,
        )


class FakeFirewall:

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


def row(
    target=TARGET,
    backend="windows_firewall",
    execution_mode="ENFORCED",
):

    return {
        "target": target,
        "status": "ACTIVE",
        "desired_state": "BLOCKED",
        "backend": backend,
        "execution_mode": execution_mode,
    }


def service(
    repository,
):

    return ResponseBlockExpirationService(
        repository=repository,
        now_provider=lambda: NOW,
    )


def real_repository():

    directory = tempfile.TemporaryDirectory()

    db = Database(
        str(
            Path(directory.name)
            / "soc.db"
        )
    )

    MigrationRunner(
        db
    ).run()

    repository = (
        ResponseBlockRepository(
            db
        )
    )

    return (
        directory,
        repository,
    )


def test_enforced_expiration_only_marks_expired():

    repository = FakeRepository([
        row()
    ])

    outcomes = service(
        repository
    ).sweep()

    assert repository.expired_calls == [
        (
            TARGET,
            NOW,
        )
    ]

    assert outcomes == [
        {
            "target": TARGET,
            "status": "EXPIRED",
            "desired_state": "UNBLOCKED",
        }
    ]


def test_simulated_expiration_only_marks_expired():

    repository = FakeRepository([
        row(
            backend="memory",
            execution_mode="SIMULATED",
        )
    ])

    outcomes = service(
        repository
    ).sweep()

    assert outcomes[0]["status"] == (
        "EXPIRED"
    )

    assert outcomes[0][
        "desired_state"
    ] == "UNBLOCKED"


def test_expiration_outcome_has_no_response_action():

    repository = FakeRepository([
        row()
    ])

    outcomes = service(
        repository
    ).sweep()

    assert "action" not in outcomes[0]


def test_mark_expired_false_is_skipped():

    repository = FakeRepository([
        row()
    ])

    repository.mark_expired_result[
        TARGET
    ] = False

    outcomes = service(
        repository
    ).sweep()

    assert outcomes[0]["status"] == (
        "SKIPPED"
    )


def test_missing_target_is_skipped():

    repository = FakeRepository([
        {
            "status": "ACTIVE",
            "desired_state": "BLOCKED",
        }
    ])

    outcomes = service(
        repository
    ).sweep()

    assert outcomes == [
        {
            "target": None,
            "status": "SKIPPED",
            "reason": (
                "Expired row has no target"
            ),
        }
    ]

    assert repository.expired_calls == []


def test_one_transition_failure_does_not_stop_next_target():

    repository = FakeRepository([
        row(TARGET),
        row(TARGET_2),
    ])

    repository.mark_expired_errors[
        TARGET
    ] = RuntimeError(
        "database write failed"
    )

    outcomes = service(
        repository
    ).sweep()

    assert [
        item["status"]
        for item in outcomes
    ] == [
        "FAILED",
        "EXPIRED",
    ]

    assert repository.expired_calls == [
        (
            TARGET,
            NOW,
        ),
        (
            TARGET_2,
            NOW,
        ),
    ]


def test_naive_clock_rejected():

    repository = FakeRepository()

    expiration = (
        ResponseBlockExpirationService(
            repository=repository,
            now_provider=lambda: datetime(
                2026,
                9,
                21,
                15,
                0,
            ),
        )
    )

    with pytest.raises(
        ValueError,
        match="timezone-aware",
    ):

        expiration.sweep()


def test_list_expired_failure_propagates():

    class Repository:

        def list_expired(
            self,
            now,
        ):

            raise RuntimeError(
                "database unavailable"
            )

    expiration = (
        ResponseBlockExpirationService(
            repository=Repository(),
            now_provider=lambda: NOW,
        )
    )

    with pytest.raises(
        RuntimeError,
        match="database unavailable",
    ):

        expiration.sweep()


def test_failed_block_past_ttl_becomes_reconcilable_unblocked():

    directory, repository = (
        real_repository()
    )

    try:

        target = "192.168.20.152"

        repository.upsert_active(
            target=target,
            expires_at=(
                NOW
                - timedelta(
                    seconds=1
                )
            ),
            execution_mode="SIMULATED",
            backend="memory",
        )

        repository.mark_failed(
            target,
            "temporary failure",
            (
                NOW
                - timedelta(
                    seconds=2
                )
            ),
        )

        outcomes = (
            ResponseBlockExpirationService(
                repository=repository,
                now_provider=lambda: NOW,
            )
            .sweep()
        )

        assert outcomes == [
            {
                "target": target,
                "status": "EXPIRED",
                "desired_state": "UNBLOCKED",
            }
        ]

        final = repository.get(
            target
        )

        assert (
            final["status"]
            == "EXPIRED"
        )

        assert (
            final["desired_state"]
            == "UNBLOCKED"
        )

        reconcilable = (
            repository.list_reconcilable(
                NOW
            )
        )

        assert [
            item["target"]
            for item in reconcilable
        ] == [
            target
        ]

    finally:

        directory.cleanup()


def test_expiration_preserves_backend_and_evidence():

    directory, repository = (
        real_repository()
    )

    try:

        expires_at = (
            NOW
            - timedelta(
                seconds=1
            )
        )

        repository.upsert_active(
            target=TARGET,
            expires_at=expires_at,
            execution_mode="ENFORCED",
            backend="windows_firewall",
            rule_name=(
                "SOC-LAB-BLOCK-"
                "192-168-20-130"
            ),
            source_incident_id=(
                "expiration-evidence"
            ),
        )

        before = repository.get(
            TARGET
        )

        ResponseBlockExpirationService(
            repository=repository,
            now_provider=lambda: NOW,
        ).sweep()

        after = repository.get(
            TARGET
        )

        assert (
            after["status"]
            == "EXPIRED"
        )

        assert (
            after["desired_state"]
            == "UNBLOCKED"
        )

        for field in (
            "created_at",
            "expires_at",
            "execution_mode",
            "backend",
            "rule_name",
            "source_incident_id",
        ):

            assert (
                after[field]
                == before[field]
            )

    finally:

        directory.cleanup()


def test_memory_history_expiration_never_touches_firewall_after_enforce_restart():

    directory, repository = (
        real_repository()
    )

    try:

        target = "192.168.20.245"

        repository.upsert_active(
            target=target,
            expires_at=(
                NOW
                - timedelta(
                    seconds=1
                )
            ),
            execution_mode="SIMULATED",
            backend="memory",
        )

        firewall = FakeFirewall(
            blocked={
                target
            }
        )

        engine = ResponseEngine(
            response_mode="enforce",
            firewall_backend=firewall,
        )

        expiration = (
            ResponseBlockExpirationService(
                repository=repository,
                now_provider=lambda: NOW,
            )
        )

        expiration_outcomes = (
            expiration.sweep()
        )

        assert (
            expiration_outcomes[0][
                "status"
            ]
            == "EXPIRED"
        )

        assert firewall.unblock_calls == []

        reconciliation = (
            ResponseBlockReconciliationService(
                repository=repository,
                response_engine=engine,
                firewall_backend=firewall,
                now_provider=lambda: NOW,
            )
        )

        recovery = (
            reconciliation.sweep()
        )

        assert (
            recovery[0]["status"]
            == "CONVERGED"
        )

        assert firewall.unblock_calls == []

        assert (
            target
            in firewall.blocked
        )

        final = repository.get(
            target
        )

        assert (
            final["status"]
            == "RELEASED"
        )

        assert (
            final["desired_state"]
            == "UNBLOCKED"
        )

    finally:

        directory.cleanup()


def test_windows_history_expiration_unblocks_windows_after_simulate_restart():

    directory, repository = (
        real_repository()
    )

    try:

        target = "192.168.20.246"

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

        firewall = FakeFirewall(
            blocked={
                target
            }
        )

        engine = ResponseEngine(
            response_mode="simulate"
        )

        expiration = (
            ResponseBlockExpirationService(
                repository=repository,
                now_provider=lambda: NOW,
            )
        )

        expiration_outcomes = (
            expiration.sweep()
        )

        assert (
            expiration_outcomes[0][
                "status"
            ]
            == "EXPIRED"
        )

        assert firewall.unblock_calls == []

        assert (
            target
            in firewall.blocked
        )

        reconciliation = (
            ResponseBlockReconciliationService(
                repository=repository,
                response_engine=engine,
                firewall_backend=firewall,
                now_provider=lambda: NOW,
            )
        )

        recovery = (
            reconciliation.sweep()
        )

        assert (
            recovery[0]["status"]
            == "REPAIRED"
        )

        assert (
            recovery[0]["action"][
                "backend"
            ]
            == "windows_firewall"
        )

        assert (
            recovery[0]["action"][
                "execution_mode"
            ]
            == "ENFORCED"
        )

        assert firewall.unblock_calls == [
            target
        ]

        assert (
            target
            not in firewall.blocked
        )

        final = repository.get(
            target
        )

        assert (
            final["status"]
            == "RELEASED"
        )

        assert (
            final["desired_state"]
            == "UNBLOCKED"
        )

    finally:

        directory.cleanup()
