class TelegramMessageBuilder:

    TRUNCATION_SUFFIX = "\n[TRUNCATED]"

    def __init__(
        self,
        max_chars=3500,
    ):

        try:

            max_chars = int(
                max_chars
            )

        except (
            TypeError,
            ValueError,
        ):

            raise ValueError(
                "Telegram max_chars "
                "must be an integer"
            ) from None

        if not (
            1
            <= max_chars
            <= 4096
        ):

            raise ValueError(
                "Telegram max_chars "
                "must be between 1 and 4096"
            )

        self.max_chars = max_chars

    # =========================================
    # PUBLIC
    # =========================================

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

        severity = self._scalar(
            plan.get(
                "severity",
                "UNKNOWN",
            )
        ).upper()

        incident_id = self._scalar(
            plan.get(
                "incident_id",
                "UNKNOWN",
            )
        )

        risk_score = self._scalar(
            plan.get(
                "risk_score",
                0,
            )
        )

        source_ip = self._scalar(
            incident.get(
                "ip",
                "UNKNOWN",
            )
        )

        rules = self._rule_ids(
            incident
        )

        mitre = self._mitre(
            incident
        )

        actions = self._actions(
            incident
        )

        lines = [
            f"[SOC][{severity}]",
            "",
            (
                "Incident: "
                f"{incident_id}"
            ),
            (
                "Risk: "
                f"{risk_score}"
            ),
            (
                "Source IP: "
                f"{source_ip}"
            ),
            (
                "MITRE: "
                + (
                    ", ".join(
                        mitre
                    )
                    if mitre
                    else "NONE"
                )
            ),
            "",
            "Detection:",
        ]

        if rules:

            lines.extend(
                f"- {rule}"
                for rule in rules
            )

        else:

            lines.append(
                "- NONE"
            )

        lines.extend([
            "",
            "Response:",
        ])

        if actions:

            for action in actions:

                lines.append(
                    "- "
                    + " | ".join(
                        (
                            action[
                                "type"
                            ],
                            action[
                                "status"
                            ],
                            action[
                                "execution_mode"
                            ],
                        )
                    )
                )

        else:

            lines.append(
                "- NONE"
            )

        message = "\n".join(
            lines
        )

        return self._bounded(
            message
        )

    # =========================================
    # NORMALIZATION
    # =========================================

    def _scalar(
        self,
        value,
    ):

        if value is None:
            value = ""

        return (
            str(value)
            .replace(
                "\r",
                " ",
            )
            .replace(
                "\n",
                " ",
            )
            .strip()
        )

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
                    self._scalar(
                        value
                    )
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

            mapping = alert.get(
                "mitre"
            )

            if not isinstance(
                mapping,
                dict,
            ):

                continue

            technique = mapping.get(
                "technique_id"
            )

            if technique:

                values.add(
                    self._scalar(
                        technique
                    )
                )

        return sorted(
            values
        )

    def _actions(
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
                "type": self._scalar(
                    action.get(
                        "type",
                        "UNKNOWN",
                    )
                ),
                "status": self._scalar(
                    action.get(
                        "status",
                        "UNKNOWN",
                    )
                ),
                "execution_mode": (
                    self._scalar(
                        action.get(
                            "execution_mode",
                            "UNKNOWN",
                        )
                    )
                ),
            })

        return safe

    # =========================================
    # LENGTH BOUND
    # =========================================

    def _bounded(
        self,
        message,
    ):

        if len(
            message
        ) <= self.max_chars:

            return message

        suffix = (
            self.TRUNCATION_SUFFIX
        )

        if (
            len(suffix)
            >= self.max_chars
        ):

            return message[
                :self.max_chars
            ]

        body_limit = (
            self.max_chars
            - len(suffix)
        )

        return (
            message[
                :body_limit
            ]
            .rstrip()
            + suffix
        )
