from copy import deepcopy

from email.message import (
    EmailMessage,
)


class EmailMessageBuilder:

    def __init__(
        self,
        sender,
        recipient,
    ):

        self.sender = sender
        self.recipient = recipient

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

        rule_ids = self._rule_ids(
            incident
        )

        mitre = self._mitre(
            incident
        )

        actions = self._actions(
            incident
        )

        message = EmailMessage()

        message[
            "Subject"
        ] = (
            f"[SOC][{severity}] "
            f"Incident {incident_id}"
        )

        message[
            "From"
        ] = self.sender

        message[
            "To"
        ] = self.recipient

        body = [
            "SOC Incident Notification",
            "",
            (
                "Incident ID: "
                f"{incident_id}"
            ),
            (
                "Severity: "
                f"{severity}"
            ),
            (
                "Risk Score: "
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

        if rule_ids:

            body.extend(
                f"- {rule_id}"
                for rule_id in rule_ids
            )

        else:

            body.append(
                "- NONE"
            )

        body.extend([
            "",
            "Response:",
        ])

        if actions:

            for action in actions:

                body.append(
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

            body.append(
                "- NONE"
            )

        message.set_content(
            "\n".join(
                body
            )
        )

        return message

    # =========================================
    # SAFE NORMALIZATION
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
            deepcopy(
                alert
            )
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
