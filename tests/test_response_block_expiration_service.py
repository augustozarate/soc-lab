from datetime import (
    datetime,
    timezone,
)

import pytest

from engine.services.response_block_expiration_service import (
    ResponseBlockExpirationService,
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
        self.released_calls = []
        self.failed_calls = []

        self.mark_expired_result = {}

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

        return self.mark_expired_result.get(
            target,
            True,
        )

    def mark_released(
        self,
        target,
        now,
    ):

        self.released_calls.append(
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

        self.failed_calls.append(
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
        results=None,
        errors=None,
    ):

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

        result = self.results[
            target
        ]

        return dict(
            result
        )


def row(
    target=TARGET,
):

    return {
        "target": target,
        "status": "ACTIVE",
        "desired_state": "BLOCKED",
    }


def service(
    repository,
    engine,
):

    return ResponseBlockExpirationService(
        repository=repository,
        response_engine=engine,
        now_provider=lambda: NOW,
    )


@pytest.mark.parametrize(
    "backend_status",
    [
        "REMOVED",
        "MISSING",
    ],
)
def test_enforced_release_converges(
    backend_status,
):

    repository = FakeRepository([
        row()
    ])

    engine = FakeEngine(
        results={
            TARGET: {
                "type": "UNBLOCK_IP",
                "target": TARGET,
                "status": "SUCCESS",
                "execution_mode": "ENFORCED",
                "backend": "windows_firewall",
                "backend_status": backend_status,
            }
        }
    )

    outcomes = service(
        repository,
        engine,
    ).sweep()

    assert (
        repository.expired_calls
        == [
            (
                TARGET,
                NOW,
            )
        ]
    )

    assert (
        repository.released_calls
        == [
            (
                TARGET,
                NOW,
            )
        ]
    )

    assert (
        repository.failed_calls
        == []
    )

    assert (
        outcomes[0]["status"]
        == "RELEASED"
    )


def test_simulated_existing_release_converges():

    repository = FakeRepository([
        row()
    ])

    engine = FakeEngine(
        results={
            TARGET: {
                "type": "UNBLOCK_IP",
                "target": TARGET,
                "status": "SIMULATED",
                "execution_mode": "SIMULATED",
                "backend": "memory",
            }
        }
    )

    outcomes = service(
        repository,
        engine,
    ).sweep()

    assert (
        outcomes[0]["status"]
        == "RELEASED"
    )

    assert len(
        repository.released_calls
    ) == 1


def test_simulated_missing_release_converges():

    repository = FakeRepository([
        row()
    ])

    engine = FakeEngine(
        results={
            TARGET: {
                "type": "UNBLOCK_IP",
                "target": TARGET,
                "status": "SKIPPED",
                "execution_mode": "SIMULATED",
                "backend": "memory",
                "reason": (
                    "IP is not simulated "
                    "as blocked"
                ),
            }
        }
    )

    outcomes = service(
        repository,
        engine,
    ).sweep()

    assert (
        outcomes[0]["status"]
        == "RELEASED"
    )


def test_wrong_skipped_reason_is_failure():

    repository = FakeRepository([
        row()
    ])

    engine = FakeEngine(
        results={
            TARGET: {
                "type": "UNBLOCK_IP",
                "target": TARGET,
                "status": "SKIPPED",
                "execution_mode": "SIMULATED",
                "backend": "memory",
                "reason": "different reason",
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
        repository.failed_calls
    ) == 1

    assert (
        repository.released_calls
        == []
    )


def test_execution_exception_marks_failed():

    repository = FakeRepository([
        row()
    ])

    engine = FakeEngine(
        errors={
            TARGET: RuntimeError(
                "firewall unavailable"
            )
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
        repository.failed_calls
    ) == 1

    assert (
        "firewall unavailable"
        in repository.failed_calls[0][1]
    )


def test_non_convergent_result_marks_failed():

    repository = FakeRepository([
        row()
    ])

    engine = FakeEngine(
        results={
            TARGET: {
                "type": "UNBLOCK_IP",
                "target": TARGET,
                "status": "FAILED",
                "error": "backend failure",
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
        repository.failed_calls
    ) == 1


def test_mark_expired_false_skips_execution():

    repository = FakeRepository([
        row()
    ])

    repository.mark_expired_result[
        TARGET
    ] = False

    engine = FakeEngine()

    outcomes = service(
        repository,
        engine,
    ).sweep()

    assert engine.calls == []

    assert (
        outcomes[0]["status"]
        == "SKIPPED"
    )


def test_one_target_failure_does_not_stop_next_target():

    repository = FakeRepository([
        row(TARGET),
        row(TARGET_2),
    ])

    engine = FakeEngine(
        errors={
            TARGET: RuntimeError(
                "first failed"
            ),
        },
        results={
            TARGET_2: {
                "type": "UNBLOCK_IP",
                "target": TARGET_2,
                "status": "SUCCESS",
                "execution_mode": "ENFORCED",
                "backend": "windows_firewall",
                "backend_status": "MISSING",
            },
        },
    )

    outcomes = service(
        repository,
        engine,
    ).sweep()

    assert [
        item["status"]
        for item in outcomes
    ] == [
        "FAILED",
        "RELEASED",
    ]

    assert len(
        engine.calls
    ) == 2

    assert len(
        repository.failed_calls
    ) == 1

    assert len(
        repository.released_calls
    ) == 1


def test_expiration_happens_before_unblock():

    order = []

    class Repository(
        FakeRepository
    ):

        def mark_expired(
            self,
            target,
            now,
        ):

            order.append(
                "mark_expired"
            )

            return True

        def mark_released(
            self,
            target,
            now,
        ):

            order.append(
                "mark_released"
            )

            return True

    class Engine(
        FakeEngine
    ):

        def execute(
            self,
            action,
        ):

            order.append(
                "execute"
            )

            return {
                "type": "UNBLOCK_IP",
                "target": TARGET,
                "status": "SUCCESS",
                "execution_mode": "ENFORCED",
                "backend": "windows_firewall",
                "backend_status": "REMOVED",
            }

    repository = Repository([
        row()
    ])

    service(
        repository,
        Engine(),
    ).sweep()

    assert order == [
        "mark_expired",
        "execute",
        "mark_released",
    ]


def test_naive_clock_rejected():

    repository = FakeRepository()

    engine = FakeEngine()

    expiration = (
        ResponseBlockExpirationService(
            repository=repository,
            response_engine=engine,
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
            response_engine=FakeEngine(),
            now_provider=lambda: NOW,
        )
    )

    with pytest.raises(
        RuntimeError,
        match="database unavailable",
    ):

        expiration.sweep()


def test_failed_block_past_ttl_can_reenter_expiration_flow():

    from pathlib import Path
    import tempfile

    from datetime import timedelta

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


    target = "192.168.20.152"

    with tempfile.TemporaryDirectory() as directory:

        db = Database(
            str(
                Path(directory)
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

        engine = ResponseEngine(
            response_mode="simulate"
        )

        engine.execute({
            "type": "BLOCK_IP",
            "target": target,
            "status": "PENDING",
        })

        assert (
            target
            in engine.blocked_ips
        )

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

        failed = repository.get(
            target
        )

        assert (
            failed["status"]
            == "FAILED"
        )

        assert (
            failed["desired_state"]
            == "BLOCKED"
        )

        expiration = (
            ResponseBlockExpirationService(
                repository=repository,
                response_engine=engine,
                now_provider=lambda: NOW,
            )
        )

        outcomes = expiration.sweep()

        assert len(
            outcomes
        ) == 1

        assert (
            outcomes[0]["status"]
            == "RELEASED"
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

        assert (
            target
            not in engine.blocked_ips
        )
