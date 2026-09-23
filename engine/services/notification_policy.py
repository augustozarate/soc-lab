import hashlib
import json


class NotificationPolicy:

    CHANNELS_BY_SEVERITY = {
        "CRITICAL": (
            "local",
            "email",
            "telegram",
            "webhook",
        ),
        "HIGH": (
            "local",
            "email",
            "telegram",
        ),
        "MEDIUM": (
            "local",
        ),
        "LOW": (),
    }

    def __init__(
        self,
        threema_enabled=False,
    ):

        self.threema_enabled = bool(
            threema_enabled
        )

    # =========================================
    # PUBLIC POLICY
    # =========================================

    def evaluate(
        self,
        incident,
        event_type="incident_persisted",
    ):

        if not isinstance(
            incident,
            dict,
        ):
            return None

        incident_id = incident.get(
            "id"
        )

        if not incident_id:
            return None

        severity = self._severity(
            incident
        )

        channels = list(
            self.CHANNELS_BY_SEVERITY.get(
                severity,
                (),
            )
        )

        if (
            self.threema_enabled
            and severity
            in {
                "CRITICAL",
                "HIGH",
            }
        ):

            channels.append(
                "threema"
            )

        if not channels:
            return None

        risk_score = self._risk_score(
            incident
        )

        return {
            "incident_id": incident_id,
            "event_type": event_type,
            "severity": severity,
            "risk_score": risk_score,
            "priority": severity,
            "channels": channels,
            "dedup_key": self._dedup_key(
                incident=incident,
                event_type=event_type,
                severity=severity,
                risk_score=risk_score,
            ),
            "reason": (
                f"severity={severity}"
            ),
        }

    # =========================================
    # NORMALIZATION
    # =========================================

    def _severity(
        self,
        incident,
    ):

        severity = incident.get(
            "severity",
            "LOW",
        )

        if severity is None:
            return "LOW"

        return str(
            severity
        ).strip().upper()

    def _risk_score(
        self,
        incident,
    ):

        value = incident.get(
            "risk_score",
            0,
        )

        try:

            return float(
                value
            )

        except (
            TypeError,
            ValueError,
        ):

            return 0.0

    # =========================================
    # DEDUPLICATION IDENTITY
    # =========================================

    def _dedup_key(
        self,
        incident,
        event_type,
        severity,
        risk_score,
    ):

        semantic_state = {
            "incident_id": incident.get(
                "id"
            ),
            "event_type": event_type,
            "severity": severity,
            "risk_score": risk_score,
            "alerts": self._alert_signatures(
                incident
            ),
            "response_actions": (
                self._response_signatures(
                    incident
                )
            ),
        }

        canonical = json.dumps(
            semantic_state,
            sort_keys=True,
            separators=(
                ",",
                ":",
            ),
            ensure_ascii=False,
            default=str,
        )

        digest = hashlib.sha256(
            canonical.encode(
                "utf-8"
            )
        ).hexdigest()

        return (
            f"notification:"
            f"{incident.get('id')}:"
            f"{digest}"
        )

    def _alert_signatures(
        self,
        incident,
    ):

        signatures = []

        for alert in incident.get(
            "alerts",
            [],
        ):

            if not isinstance(
                alert,
                dict,
            ):
                continue

            mitre = alert.get(
                "mitre"
            )

            if not isinstance(
                mitre,
                dict,
            ):
                mitre = {}

            signatures.append({
                "type": (
                    alert.get("rule_id")
                    or alert.get("type")
                ),
                "ip": alert.get(
                    "ip"
                ),
                "technique_id": (
                    mitre.get(
                        "technique_id"
                    )
                ),
            })

        return sorted(
            signatures,
            key=lambda item: (
                str(
                    item.get("type")
                    or ""
                ),
                str(
                    item.get("ip")
                    or ""
                ),
                str(
                    item.get("technique_id")
                    or ""
                ),
            ),
        )

    def _response_signatures(
        self,
        incident,
    ):

        signatures = []

        for action in incident.get(
            "response_actions",
            [],
        ):

            if not isinstance(
                action,
                dict,
            ):
                continue

            signatures.append({
                "type": action.get(
                    "type"
                ),
                "target": action.get(
                    "target"
                ),
                "status": action.get(
                    "status"
                ),
                "execution_mode": (
                    action.get(
                        "execution_mode"
                    )
                ),
                "backend": action.get(
                    "backend"
                ),
            })

        return sorted(
            signatures,
            key=lambda item: (
                str(
                    item.get("type")
                    or ""
                ),
                str(
                    item.get("target")
                    or ""
                ),
                str(
                    item.get("status")
                    or ""
                ),
                str(
                    item.get("execution_mode")
                    or ""
                ),
                str(
                    item.get("backend")
                    or ""
                ),
            ),
        )
