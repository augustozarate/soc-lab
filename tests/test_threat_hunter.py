from datetime import (
    datetime,
    timedelta,
    timezone,
)

from engine.services.threat_hunter import (
    ThreatHunter,
)


def make_incident():
    return {
        "ip": "192.168.20.130",
    }


def test_aware_utc_timestamp_does_not_raise():
    timestamp = (
        datetime.now(timezone.utc)
        - timedelta(minutes=1)
    ).isoformat()

    hunter = ThreatHunter([
        {
            "timestamp": timestamp,
            "ip": "192.168.20.130",
        }
    ])

    result = hunter.hunt(
        make_incident()
    )

    assert isinstance(
        result,
        list,
    )


def test_z_timestamp_does_not_raise():
    timestamp = (
        datetime.now(timezone.utc)
        - timedelta(minutes=1)
    ).isoformat().replace(
        "+00:00",
        "Z",
    )

    hunter = ThreatHunter([
        {
            "timestamp": timestamp,
            "ip": "192.168.20.130",
        }
    ])

    result = hunter.hunt(
        make_incident()
    )

    assert isinstance(
        result,
        list,
    )


def test_naive_timestamp_remains_supported():
    timestamp = (
        datetime.now(timezone.utc)
        - timedelta(minutes=1)
    ).replace(
        tzinfo=None
    ).isoformat()

    hunter = ThreatHunter([
        {
            "timestamp": timestamp,
            "ip": "192.168.20.130",
        }
    ])

    result = hunter.hunt(
        make_incident()
    )

    assert isinstance(
        result,
        list,
    )


def test_old_aware_event_is_filtered():
    timestamp = (
        datetime.now(timezone.utc)
        - timedelta(minutes=31)
    ).isoformat()

    hunter = ThreatHunter([
        {
            "timestamp": timestamp,
            "ip": "192.168.20.130",
            "action": "login_failed",
        }
    ])

    result = hunter.hunt(
        make_incident()
    )

    assert result == []


def test_invalid_timestamp_is_ignored():
    hunter = ThreatHunter([
        {
            "timestamp": "not-a-timestamp",
            "ip": "192.168.20.130",
        }
    ])

    result = hunter.hunt(
        make_incident()
    )

    assert result == []
