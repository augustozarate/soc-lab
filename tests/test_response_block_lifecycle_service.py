from datetime import (
    datetime,
    timedelta,
    timezone,
)

import pytest

from engine.services.response_block_lifecycle_service import (
    ResponseBlockLifecycleService,
)


TARGET = "192.168.20.130"


class FakeRepository:

    def __init__(self):

        self.calls = []

    def upsert_active(
        self,
        **kwargs,
    ):

        self.calls.append(
            kwargs
        )

        return kwargs


NOW = datetime(
    2026,
    9,
    21,
    4,
    0,
    tzinfo=timezone.utc,
)


def build_service(
    ttl_seconds=900,
):

    repository = FakeRepository()

    service = ResponseBlockLifecycleService(
        repository=repository,
        ttl_seconds=ttl_seconds,
        now_provider=lambda: NOW,
    )

    return (
        service,
        repository,
    )


def incident():

    return {
        "id": "incident-ttl",
        "ip": TARGET,
    }


def test_enforced_created_creates_active_lifecycle():

    service, repository = (
        build_service()
    )

    result = service.observe(
        {
            "type": "BLOCK_IP",
            "target": TARGET,
            "status": "SUCCESS",
            "execution_mode": "ENFORCED",
            "backend": "windows_firewall",
            "backend_status": "CREATED",
            "rule_name": (
                "SOC-LAB-BLOCK-"
                "192-168-20-130"
            ),
        },
        incident(),
    )

    assert result is not None
    assert len(repository.calls) == 1

    call = repository.calls[0]

    assert call["target"] == TARGET
    assert (
        call["execution_mode"]
        == "ENFORCED"
    )
    assert (
        call["backend"]
        == "windows_firewall"
    )
    assert (
        call["source_incident_id"]
        == "incident-ttl"
    )
    assert (
        call["expires_at"]
        == NOW + timedelta(
            seconds=900
        )
    )


def test_enforced_exists_refreshes_lifecycle():

    service, repository = (
        build_service()
    )

    service.observe(
        {
            "type": "BLOCK_IP",
            "target": TARGET,
            "status": "SUCCESS",
            "execution_mode": "ENFORCED",
            "backend": "windows_firewall",
            "backend_status": "EXISTS",
            "rule_name": (
                "SOC-LAB-BLOCK-"
                "192-168-20-130"
            ),
        },
        incident(),
    )

    assert len(repository.calls) == 1


def test_simulated_memory_block_is_durable():

    service, repository = (
        build_service()
    )

    service.observe(
        {
            "type": "BLOCK_IP",
            "target": TARGET,
            "status": "SIMULATED",
            "execution_mode": "SIMULATED",
            "backend": "memory",
        },
        incident(),
    )

    assert len(repository.calls) == 1

    assert (
        repository.calls[0]["backend"]
        == "memory"
    )


def test_duplicate_memory_block_refreshes_lifecycle():

    service, repository = (
        build_service()
    )

    service.observe(
        {
            "type": "BLOCK_IP",
            "target": TARGET,
            "status": "SKIPPED",
            "execution_mode": "SIMULATED",
            "backend": "memory",
            "reason": (
                "IP already simulated "
                "as blocked"
            ),
        },
        incident(),
    )

    assert len(repository.calls) == 1


@pytest.mark.parametrize(
    "action",
    [
        {
            "type": "BLOCK_IP",
            "target": TARGET,
            "status": "SIMULATED",
            "execution_mode": "SIMULATED",
            "backend": "simulation",
        },
        {
            "type": "BLOCK_IP",
            "target": TARGET,
            "status": "PROTECTED",
            "execution_mode": "PROTECTED",
            "backend": "safety_policy",
        },
        {
            "type": "BLOCK_IP",
            "target": TARGET,
            "status": "FAILED",
        },
        {
            "type": "UNBLOCK_IP",
            "target": TARGET,
            "status": "SUCCESS",
            "execution_mode": "ENFORCED",
            "backend": "windows_firewall",
            "backend_status": "REMOVED",
        },
        {
            "type": "NOTIFY_SOC",
            "target": "SOC_TEAM",
            "status": "SUCCESS",
            "execution_mode": "LOCAL",
            "backend": "console",
        },
        {
            "type": "BLOCK_IP",
            "target": TARGET,
            "status": "SUCCESS",
            "execution_mode": "ENFORCED",
            "backend": "windows_firewall",
            "backend_status": "UNKNOWN",
        },
        {
            "type": "BLOCK_IP",
            "target": TARGET,
            "status": "SKIPPED",
            "execution_mode": "SIMULATED",
            "backend": "memory",
            "reason": "some other reason",
        },
    ],
)
def test_non_durable_results_are_ignored(
    action,
):

    service, repository = (
        build_service()
    )

    assert (
        service.observe(
            action,
            incident(),
        )
        is None
    )

    assert repository.calls == []


def test_missing_target_is_ignored():

    service, repository = (
        build_service()
    )

    result = service.observe(
        {
            "type": "BLOCK_IP",
            "status": "SIMULATED",
            "execution_mode": "SIMULATED",
            "backend": "memory",
        },
        incident(),
    )

    assert result is None
    assert repository.calls == []


@pytest.mark.parametrize(
    "ttl",
    [
        0,
        -1,
    ],
)
def test_invalid_ttl_rejected(
    ttl,
):

    with pytest.raises(
        ValueError,
        match="greater than 0",
    ):

        ResponseBlockLifecycleService(
            repository=FakeRepository(),
            ttl_seconds=ttl,
        )


def test_naive_now_provider_rejected():

    repository = FakeRepository()

    service = ResponseBlockLifecycleService(
        repository=repository,
        ttl_seconds=900,
        now_provider=lambda: datetime(
            2026,
            9,
            21,
            4,
            0,
        ),
    )

    with pytest.raises(
        ValueError,
        match="timezone-aware",
    ):

        service.observe(
            {
                "type": "BLOCK_IP",
                "target": TARGET,
                "status": "SIMULATED",
                "execution_mode": "SIMULATED",
                "backend": "memory",
            },
            incident(),
        )


def test_repository_failure_propagates():

    class FailingRepository:

        def upsert_active(
            self,
            **kwargs,
        ):

            raise RuntimeError(
                "database unavailable"
            )

    service = ResponseBlockLifecycleService(
        repository=FailingRepository(),
        ttl_seconds=900,
        now_provider=lambda: NOW,
    )

    with pytest.raises(
        RuntimeError,
        match="database unavailable",
    ):

        service.observe(
            {
                "type": "BLOCK_IP",
                "target": TARGET,
                "status": "SIMULATED",
                "execution_mode": "SIMULATED",
                "backend": "memory",
            },
            incident(),
        )
