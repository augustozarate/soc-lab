class WebhookPayloadBuilder:

    SCHEMA_VERSION = "1"

    def build(
        self,
        plan,
        incident,
    ):

        if not isinstance(
            plan,
            dict,
        ):

            plan = {}

        if not isinstance(
            incident,
            dict,
        ):

            incident = {}

        return {
            "schema_version": (
                self.SCHEMA_VERSION
            ),
            "event_type": plan.get(
                "event_type"
            ),
            "incident_id": plan.get(
                "incident_id"
            ),
            "severity": plan.get(
                "severity"
            ),
            "risk_score": plan.get(
                "risk_score"
            ),
            "timestamp": (
                incident.get(
                    "updated_at"
                )
                or incident.get(
                    "created_at"
                )
                or plan.get(
                    "timestamp"
                )
            ),
            "source": {
                "ip": incident.get(
                    "ip"
                ),
            },
            "detection": {
                "rule_ids": (
                    self._rule_ids(
                        incident
                    )
                ),
            },
            "mitre": self._mitre(
                incident
            ),
            "response_actions": (
                self._response_actions(
                    incident
                )
            ),
        }

    def _alerts(
        self,
        incident,
    ):

        alerts = incident.get(
            "alerts",
            [],
        )

        if not isinstance(
            alerts,
            (
                list,
                tuple,
            ),
        ):

            return []

        return [
            alert
            for alert in alerts
            if isinstance(
                alert,
                dict,
            )
        ]

    def _rule_ids(
        self,
        incident,
    ):

        values = set()

        for alert in self._alerts(
            incident
        ):

            value = (
                alert.get(
                    "rule_id"
                )
                or alert.get(
                    "type"
                )
            )

            if value:

                values.add(
                    str(value)
                )

        return sorted(
            values
        )

    def _mitre(
        self,
        incident,
    ):

        values = set()

        for alert in self._alerts(
            incident
        ):

            mitre = alert.get(
                "mitre"
            )

            if not isinstance(
                mitre,
                dict,
            ):

                continue

            technique = mitre.get(
                "technique_id"
            )

            if technique:

                values.add(
                    str(
                        technique
                    )
                )

        return sorted(
            values
        )

    def _response_actions(
        self,
        incident,
    ):

        actions = incident.get(
            "response_actions",
            [],
        )

        if not isinstance(
            actions,
            (
                list,
                tuple,
            ),
        ):

            return []

        safe = []

        for action in actions:

            if not isinstance(
                action,
                dict,
            ):

                continue

            safe.append({
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

        return safe
