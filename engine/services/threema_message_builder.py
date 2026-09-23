class ThreemaMessageBuilder:

    TRUNCATION_SUFFIX = "\n[TRUNCATED]"

    # Conservative plaintext limit.
    #
    # Threema Gateway limits the encrypted
    # E2E box to 7812 bytes. The SDK still
    # needs room for:
    #
    # - message type
    # - randomized protocol padding
    # - authenticated-encryption overhead
    #
    # Keep plaintext below that transport
    # ceiling instead of relying on provider
    # rejection.
    MAX_SAFE_PLAINTEXT_BYTES = 7000

    def __init__(
        self,
        max_bytes=7000,
    ):

        if isinstance(
            max_bytes,
            bool,
        ):

            raise ValueError(
                "Threema max_bytes "
                "must be an integer"
            )

        try:

            max_bytes = int(
                max_bytes
            )

        except (
            TypeError,
            ValueError,
        ):

            raise ValueError(
                "Threema max_bytes "
                "must be an integer"
            ) from None

        if not (
            1
            <= max_bytes
            <= self.MAX_SAFE_PLAINTEXT_BYTES
        ):

            raise ValueError(
                "Threema max_bytes "
                "must be between 1 and "
                f"{self.MAX_SAFE_PLAINTEXT_BYTES}"
            )

        self.max_bytes = max_bytes

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
    # UTF-8 BYTE BOUND
    # =========================================

    def _bounded(
        self,
        message,
    ):

        encoded = message.encode(
            "utf-8"
        )

        if len(
            encoded
        ) <= self.max_bytes:

            return message

        suffix = (
            self.TRUNCATION_SUFFIX
        )

        suffix_bytes = suffix.encode(
            "utf-8"
        )

        if len(
            suffix_bytes
        ) >= self.max_bytes:

            return (
                encoded[
                    :self.max_bytes
                ]
                .decode(
                    "utf-8",
                    errors="ignore",
                )
            )

        body_limit = (
            self.max_bytes
            - len(
                suffix_bytes
            )
        )

        body = (
            encoded[
                :body_limit
            ]
            .decode(
                "utf-8",
                errors="ignore",
            )
            .rstrip()
        )

        candidate = (
            body
            + suffix
        )

        while (
            len(
                candidate.encode(
                    "utf-8"
                )
            )
            > self.max_bytes
            and body
        ):

            body = body[:-1]

            candidate = (
                body.rstrip()
                + suffix
            )

        return candidate
