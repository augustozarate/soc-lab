import requests

from engine.services.threat_intel import ThreatIntel


TEST_IP = "203.0.113.250"


def build_threat_intel(
    monkeypatch,
):
    """
    Build ThreatIntel without reading or writing
    persistent threat-intelligence state.
    """

    monkeypatch.setattr(
        "engine.services.threat_intel.AIMemory.__init__",
        lambda self, *args, **kwargs: None,
    )

    ti = ThreatIntel()

    ti.memory.memory = {
        "ips": {},
    }
    ti.memory.dirty = False

    ti.cache.clear()

    ti.abuse_key = None
    ti.vt_key = None

    ti.external_failure_count = 0
    ti.external_circuit_opened_at = None
    ti.external_probe_in_flight = False

    return ti


def test_offline_preflight_falls_back_to_heuristic(
    monkeypatch,
):
    ti = build_threat_intel(
        monkeypatch
    )

    ti.abuse_key = "test-abuse-key"

    monkeypatch.setattr(
        ti,
        "_external_preflight_available",
        lambda: False,
    )

    http_calls = 0

    def unexpected_http(*args, **kwargs):
        nonlocal http_calls
        http_calls += 1

        raise AssertionError(
            "HTTP request must not occur "
            "after failed preflight"
        )

    monkeypatch.setattr(
        "engine.services.threat_intel.requests.get",
        unexpected_http,
    )

    result = ti.check_ip(
        TEST_IP
    )

    assert result["source"] == "heuristic"

    assert http_calls == 0

    assert (
        ti.external_failure_count
        == 1
    )

    assert (
        ti.external_circuit_opened_at
        is not None
    )

    assert (
        ti.external_probe_in_flight
        is False
    )


def test_connectivity_error_opens_external_circuit(
    monkeypatch,
):
    ti = build_threat_intel(
        monkeypatch
    )

    ti.abuse_key = "test-abuse-key"

    monkeypatch.setattr(
        ti,
        "_external_preflight_available",
        lambda: True,
    )

    def connection_failure(
        *args,
        **kwargs,
    ):
        raise requests.exceptions.ConnectionError(
            "offline"
        )

    monkeypatch.setattr(
        "engine.services.threat_intel.requests.get",
        connection_failure,
    )

    result = ti.check_ip(
        TEST_IP
    )

    assert result["source"] == "heuristic"

    assert (
        ti.external_failure_count
        == 1
    )

    assert (
        ti.external_circuit_opened_at
        is not None
    )

    assert (
        ti.external_probe_in_flight
        is False
    )


def test_http_429_does_not_open_connectivity_circuit(
    monkeypatch,
):
    ti = build_threat_intel(
        monkeypatch
    )

    ti.abuse_key = "test-abuse-key"

    monkeypatch.setattr(
        ti,
        "_external_preflight_available",
        lambda: True,
    )

    class Response:
        status_code = 429

    http_calls = 0

    def rate_limited(
        *args,
        **kwargs,
    ):
        nonlocal http_calls
        http_calls += 1

        return Response()

    monkeypatch.setattr(
        "engine.services.threat_intel.requests.get",
        rate_limited,
    )

    result = ti.check_ip(
        TEST_IP
    )

    assert result["source"] == "heuristic"

    assert http_calls == 1

    assert (
        ti.external_failure_count
        == 0
    )

    assert (
        ti.external_circuit_opened_at
        is None
    )

    assert (
        ti.external_probe_in_flight
        is False
    )


def test_http_5xx_does_not_open_connectivity_circuit(
    monkeypatch,
):
    ti = build_threat_intel(
        monkeypatch
    )

    ti.abuse_key = "test-abuse-key"

    monkeypatch.setattr(
        ti,
        "_external_preflight_available",
        lambda: True,
    )

    class Response:
        status_code = 503

    http_calls = 0

    def server_failure(
        *args,
        **kwargs,
    ):
        nonlocal http_calls
        http_calls += 1

        return Response()

    monkeypatch.setattr(
        "engine.services.threat_intel.requests.get",
        server_failure,
    )

    result = ti.check_ip(
        TEST_IP
    )

    assert result["source"] == "heuristic"

    assert http_calls == 1

    assert (
        ti.external_failure_count
        == 0
    )

    assert (
        ti.external_circuit_opened_at
        is None
    )

    assert (
        ti.external_probe_in_flight
        is False
    )


def test_open_circuit_skips_external_preflight(
    monkeypatch,
):
    ti = build_threat_intel(
        monkeypatch
    )

    ti.abuse_key = "test-abuse-key"

    ti._record_external_connectivity_failure()

    preflight_calls = 0
    http_calls = 0

    def unexpected_preflight():
        nonlocal preflight_calls
        preflight_calls += 1

        raise AssertionError(
            "Preflight must not run "
            "while circuit is open"
        )

    def unexpected_http(*args, **kwargs):
        nonlocal http_calls
        http_calls += 1

        raise AssertionError(
            "HTTP must not run "
            "while circuit is open"
        )

    monkeypatch.setattr(
        ti,
        "_external_preflight_available",
        unexpected_preflight,
    )

    monkeypatch.setattr(
        "engine.services.threat_intel.requests.get",
        unexpected_http,
    )

    result = ti.check_ip(
        TEST_IP
    )

    assert result["source"] == "heuristic"

    assert preflight_calls == 0
    assert http_calls == 0

    assert (
        ti.external_failure_count
        == 1
    )

    assert (
        ti.external_circuit_opened_at
        is not None
    )

    assert (
        ti.external_probe_in_flight
        is False
    )


def test_probe_in_flight_skips_external_lookup(
    monkeypatch,
):
    ti = build_threat_intel(
        monkeypatch
    )

    ti.abuse_key = "test-abuse-key"
    ti.external_probe_in_flight = True

    preflight_calls = 0
    http_calls = 0

    def unexpected_preflight():
        nonlocal preflight_calls
        preflight_calls += 1

        raise AssertionError(
            "Concurrent probe must not "
            "start another preflight"
        )

    def unexpected_http(*args, **kwargs):
        nonlocal http_calls
        http_calls += 1

        raise AssertionError(
            "Concurrent probe must not "
            "start HTTP"
        )

    monkeypatch.setattr(
        ti,
        "_external_preflight_available",
        unexpected_preflight,
    )

    monkeypatch.setattr(
        "engine.services.threat_intel.requests.get",
        unexpected_http,
    )

    result = ti.check_ip(
        TEST_IP
    )

    assert result["source"] == "heuristic"

    assert preflight_calls == 0
    assert http_calls == 0

    assert (
        ti.external_failure_count
        == 0
    )

    # This test simulates another worker owning
    # the probe, so this instance must not release it.
    assert (
        ti.external_probe_in_flight
        is True
    )


def test_cache_hit_skips_external_lookup(
    monkeypatch,
):
    ti = build_threat_intel(
        monkeypatch
    )

    cached = {
        "reputation": "suspicious",
        "confidence": 88,
        "country": "ZZ",
        "known_attack": True,
        "source": "cached-test",
    }

    import time

    ti.cache[TEST_IP] = (
        cached,
        time.time(),
    )

    external_calls = 0

    def unexpected_external(ip):
        nonlocal external_calls
        external_calls += 1

        raise AssertionError(
            "External lookup must not run "
            "on a valid cache hit"
        )

    monkeypatch.setattr(
        ti,
        "_external_lookup",
        unexpected_external,
    )

    result = ti.check_ip(
        TEST_IP
    )

    assert result is cached
    assert external_calls == 0


def test_local_db_hit_populates_cache_and_skips_external(
    monkeypatch,
):
    ti = build_threat_intel(
        monkeypatch
    )

    ti.memory.memory["ips"][TEST_IP] = {
        "reputation": "suspicious",
        "confidence": 91,
        "country": "AR",
        "known_attack": True,
    }

    external_calls = 0

    def unexpected_external(ip):
        nonlocal external_calls
        external_calls += 1

        raise AssertionError(
            "External lookup must not run "
            "on a local DB hit"
        )

    monkeypatch.setattr(
        ti,
        "_external_lookup",
        unexpected_external,
    )

    result = ti.check_ip(
        TEST_IP
    )

    assert result == {
        "reputation": "suspicious",
        "confidence": 91,
        "country": "AR",
        "known_attack": True,
        "source": "local_db",
    }

    assert external_calls == 0
    assert TEST_IP in ti.cache
    assert ti.cache[TEST_IP][0] == result


def test_abuseipdb_success_is_returned_and_cached(
    monkeypatch,
):
    ti = build_threat_intel(
        monkeypatch
    )

    ti.abuse_key = "test-abuse-key"
    ti.vt_key = None

    monkeypatch.setattr(
        ti,
        "_external_preflight_available",
        lambda: True,
    )

    class Response:
        status_code = 200

        @staticmethod
        def json():
            return {
                "data": {
                    "abuseConfidenceScore": 85,
                    "countryCode": "AR",
                }
            }

    http_calls = 0

    def successful_request(
        *args,
        **kwargs,
    ):
        nonlocal http_calls
        http_calls += 1

        return Response()

    monkeypatch.setattr(
        "engine.services.threat_intel.requests.get",
        successful_request,
    )

    result = ti.check_ip(
        TEST_IP
    )

    assert http_calls == 1

    assert result == {
        "reputation": "suspicious",
        "confidence": 85,
        "country": "AR",
        "known_attack": True,
        "source": "abuseipdb",
    }

    assert TEST_IP in ti.cache

    assert (
        ti.memory.memory["ips"][TEST_IP]["source"]
        == "abuseipdb"
    )

    assert ti.memory.dirty is True

    assert (
        ti.external_probe_in_flight
        is False
    )


def test_virustotal_success_is_returned_and_cached(
    monkeypatch,
):
    ti = build_threat_intel(
        monkeypatch
    )

    ti.abuse_key = None
    ti.vt_key = "test-vt-key"

    monkeypatch.setattr(
        ti,
        "_external_preflight_available",
        lambda: True,
    )

    class Response:
        status_code = 200

        @staticmethod
        def json():
            return {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 3,
                            "suspicious": 1,
                        }
                    }
                }
            }

    http_calls = 0

    def successful_request(
        *args,
        **kwargs,
    ):
        nonlocal http_calls
        http_calls += 1

        return Response()

    monkeypatch.setattr(
        "engine.services.threat_intel.requests.get",
        successful_request,
    )

    result = ti.check_ip(
        TEST_IP
    )

    assert http_calls == 1

    assert result == {
        "reputation": "suspicious",
        "confidence": 70,
        "country": "UNKNOWN",
        "known_attack": True,
        "source": "virustotal",
    }

    assert TEST_IP in ti.cache

    assert (
        ti.memory.memory["ips"][TEST_IP]["source"]
        == "virustotal"
    )

    assert ti.memory.dirty is True

    assert (
        ti.external_probe_in_flight
        is False
    )


def test_expired_circuit_recovers(
    monkeypatch,
):
    ti = build_threat_intel(
        monkeypatch
    )

    ti.external_failure_count = 1
    ti.external_circuit_opened_at = 100.0
    ti.external_circuit_cooldown = 60.0

    monkeypatch.setattr(
        "engine.services.threat_intel.time.monotonic",
        lambda: 161.0,
    )

    assert (
        ti._external_circuit_open()
        is False
    )

    assert (
        ti.external_failure_count
        == 0
    )

    assert (
        ti.external_circuit_opened_at
        is None
    )


def test_unexpired_circuit_remains_open(
    monkeypatch,
):
    ti = build_threat_intel(
        monkeypatch
    )

    ti.external_failure_count = 1
    ti.external_circuit_opened_at = 100.0
    ti.external_circuit_cooldown = 60.0

    monkeypatch.setattr(
        "engine.services.threat_intel.time.monotonic",
        lambda: 159.0,
    )

    assert (
        ti._external_circuit_open()
        is True
    )

    assert (
        ti.external_failure_count
        == 1
    )

    assert (
        ti.external_circuit_opened_at
        == 100.0
    )
