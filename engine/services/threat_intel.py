import random
import socket
import threading
import time

import requests

from engine.config import (
    ABUSE_KEY,
    THREAT_INTEL_PREFLIGHT_ENABLED,
    THREAT_INTEL_PREFLIGHT_HOST,
    THREAT_INTEL_PREFLIGHT_PORT,
    THREAT_INTEL_PREFLIGHT_TIMEOUT,
    VT_KEY,
)
from engine.storage.ai_memory import AIMemory


class ThreatIntel:

    def __init__(self):

        self.memory = AIMemory(
            "data/threat_intel.json"
        )

        # Cache runtime
        self.cache = {}
        self.cache_ttl = 300

        # Rate limiting
        self.last_api_call = {
            "abuse": 0,
            "vt": 0
        }

        self.api_rate_limit = {
            "abuse": 1,
            "vt": 15
        }

        # External provider circuit breaker.
        #
        # Connectivity failures temporarily suspend
        # external lookups so an offline SOC runtime
        # does not repeatedly block worker execution.
        self.external_failure_count = 0
        self.external_failure_threshold = 1
        self.external_circuit_opened_at = None
        self.external_circuit_cooldown = 60.0

        # Only one worker may perform an external
        # connectivity probe at a time. Other workers
        # fail open to local/heuristic enrichment.
        self.external_probe_lock = threading.RLock()
        self.external_probe_in_flight = False

        # Fast connectivity preflight.
        #
        # This prevents an isolated/offline runtime
        # from entering a slow system DNS resolution.
        self.external_preflight_enabled = (
            THREAT_INTEL_PREFLIGHT_ENABLED
        )

        self.external_preflight_host = (
            THREAT_INTEL_PREFLIGHT_HOST
        )

        self.external_preflight_port = (
            THREAT_INTEL_PREFLIGHT_PORT
        )

        self.external_preflight_timeout = (
            THREAT_INTEL_PREFLIGHT_TIMEOUT
        )

        # API keys
        self.abuse_key = ABUSE_KEY
        self.vt_key = VT_KEY

    # =========================
    # MAIN ENTRYPOINT
    # =========================
    def check_ip(self, ip):

        now = time.time()
        print(f"[TI] Checking IP: {ip}")

        # 1️⃣ CACHE
        if ip in self.cache:
            data, ts = self.cache[ip]
            if now - ts < self.cache_ttl:
                print("[TI] Source: CACHE")
                return data

        db = self.memory.memory.get("ips", {})

        # 2️⃣ LOCAL DB
        if ip in db:
            result = self._normalize(db[ip])
            self.cache[ip] = (result, now)
            print("[TI] Source: LOCAL DB")
            return result

        # 3️⃣ EXTERNAL APIs
        result = self._external_lookup(ip)

        if result:
            self.cache[ip] = (result, now)

            db = self.memory.memory.setdefault("ips", {})
            db[ip] = {
                **result,
                "history": []
            }

            self.memory.dirty = True
            print(f"[TI] Source: {result.get('source')}")
            return result

        # 4️⃣ FALLBACK
        result = self._heuristic_lookup(ip)
        self.cache[ip] = (result, now)

        print("[TI] Source: HEURISTIC")
        return result

    # =========================
    # EXTERNAL CIRCUIT BREAKER
    # =========================
    def _external_circuit_open(self):

        with self.external_probe_lock:

            opened_at = (
                self.external_circuit_opened_at
            )

            if opened_at is None:
                return False

            elapsed = (
                time.monotonic()
                - opened_at
            )

            if (
                elapsed
                >= self.external_circuit_cooldown
            ):
                self.external_failure_count = 0
                self.external_circuit_opened_at = None

                return False

            return True

    def _record_external_connectivity_failure(
        self
    ):

        with self.external_probe_lock:

            self.external_failure_count += 1

            if (
                self.external_failure_count
                >= self.external_failure_threshold
            ):
                self.external_circuit_opened_at = (
                    time.monotonic()
                )

    def _claim_external_probe(self):

        with self.external_probe_lock:

            if self._external_circuit_open():
                return False

            if self.external_probe_in_flight:
                return False

            self.external_probe_in_flight = True

            return True

    def _release_external_probe(self):

        with self.external_probe_lock:
            self.external_probe_in_flight = False

    def _external_preflight_available(self):

        if not self.external_preflight_enabled:
            return True

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(
            self.external_preflight_timeout
        )

        try:

            result = sock.connect_ex(
                (
                    self.external_preflight_host,
                    self.external_preflight_port
                )
            )

            return result == 0

        except OSError:

            return False

        finally:

            sock.close()

    def _external_request_failed(
        self,
        error
    ):

        if isinstance(
            error,
            (
                requests.exceptions.ConnectionError,
                requests.exceptions.Timeout
            )
        ):
            self._record_external_connectivity_failure()

            print(
                "[TI] External connectivity unavailable"
            )

            return True

        return False

    # =========================
    # EXTERNAL LOOKUP (smart)
    # =========================
    def _external_lookup(self, ip):

        if not self._claim_external_probe():

            if self._external_circuit_open():
                print(
                    "[TI] External lookup skipped: "
                    "circuit open"
                )
            else:
                print(
                    "[TI] External lookup skipped: "
                    "probe already in flight"
                )

            return None

        try:

            if not self._external_preflight_available():

                self._record_external_connectivity_failure()

                print(
                    "[TI] External preflight unavailable"
                )

                return None

            # AbuseIPDB
            if self.abuse_key:
                now = time.time()

                if (
                    now
                    - self.last_api_call["abuse"]
                    >= self.api_rate_limit["abuse"]
                ):
                    self.last_api_call["abuse"] = now

                    data = self._check_abuseipdb(
                        ip
                    )

                    if data:
                        print(
                            "[TI] Source: ABUSEIPDB"
                        )
                        return data

                    if self._external_circuit_open():
                        return None

            # VirusTotal
            if self.vt_key:
                now = time.time()

                if (
                    now
                    - self.last_api_call["vt"]
                    >= self.api_rate_limit["vt"]
                ):
                    self.last_api_call["vt"] = now

                    data = self._check_virustotal(
                        ip
                    )

                    if data:
                        print(
                            "[TI] Source: VIRUSTOTAL"
                        )
                        return data

            return None

        finally:
            self._release_external_probe()

    # =========================
    # ABUSEIPDB
    # =========================
    def _check_abuseipdb(self, ip):
        try:
            url = "https://api.abuseipdb.com/api/v2/check"

            headers = {
                "Key": self.abuse_key,
                "Accept": "application/json"
            }

            params = {
                "ipAddress": ip,
                "maxAgeInDays": 90
            }

            r = requests.get(url, headers=headers, params=params, timeout=5)

            if r.status_code == 429:
                print("[TI] AbuseIPDB rate limit hit")
                return None

            if r.status_code >= 500:
                return None

            if r.status_code != 200:
                return None

            data = r.json()["data"]
            score = data["abuseConfidenceScore"]

            return {
                "reputation": "suspicious" if score > 60 else "clean",
                "confidence": score,
                "country": data.get("countryCode", "UNKNOWN"),
                "known_attack": score > 70,
                "source": "abuseipdb"
            }

        except requests.exceptions.RequestException as error:

            self._external_request_failed(
                error
            )

            return None

        except Exception:
            return None

    # =========================
    # VIRUSTOTAL
    # =========================
    def _check_virustotal(self, ip):
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

            headers = {
                "x-apikey": self.vt_key
            }

            r = requests.get(url, headers=headers, timeout=5)

            if r.status_code == 429:
                print("[TI] VirusTotal rate limit hit")
                return None

            if r.status_code >= 500:
                return None

            if r.status_code != 200:
                return None

            stats = r.json()["data"]["attributes"]["last_analysis_stats"]

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            score = malicious * 20 + suspicious * 10

            return {
                "reputation": "suspicious" if score > 50 else "clean",
                "confidence": min(score, 100),
                "country": "UNKNOWN",
                "known_attack": malicious > 0,
                "source": "virustotal"
            }

        except requests.exceptions.RequestException as error:

            self._external_request_failed(
                error
            )

            return None

        except Exception:
            return None

    # =========================
    # NORMALIZE LOCAL
    # =========================
    def _normalize(self, data):
        return {
            "reputation": data.get("reputation", "unknown"),
            "confidence": data.get("confidence", 50),
            "country": data.get("country", "UNKNOWN"),
            "known_attack": data.get("known_attack", False),
            "source": "local_db"
        }

    # =========================
    # HEURISTIC
    # =========================
    def _heuristic_lookup(self, ip):

        if ip.startswith(("10.", "192.168.")):
            reputation = "internal"
            confidence = 40
        elif ip.startswith(("185.", "45.")):
            reputation = "suspicious"
            confidence = 65
        else:
            reputation = "unknown"
            confidence = random.randint(30, 60)

        return {
            "reputation": reputation,
            "confidence": confidence,
            "country": "UNKNOWN",
            "known_attack": False,
            "source": "heuristic"
        }

    def learn_from_incident(self, ip, risk):

        if not ip:
            return

        db = self.memory.memory.setdefault("ips", {})

        if ip not in db:
            db[ip] = {
                "reputation": "unknown",
                "confidence": 50,
                "country": "UNKNOWN",
                "known_attack": False,
                "source": "learned",
                "history": []
            }

        data = db[ip]

        data.setdefault("history", []).append(risk)

        avg_risk = sum(data["history"]) / len(data["history"])

        data["confidence"] = min(100, int(avg_risk))

        if avg_risk >= 80:
            data["reputation"] = "suspicious"
            data["known_attack"] = True
        elif avg_risk < 40:
            data["reputation"] = "clean"

        self.memory.dirty = True
