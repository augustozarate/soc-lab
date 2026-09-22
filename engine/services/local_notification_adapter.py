from engine.cli.console_io import (
    safe_print,
)


class LocalNotificationAdapter:

    def __init__(
        self,
        writer=None,
    ):

        self.writer = (
            writer
            or safe_print
        )

    def send(
        self,
        plan,
        incident,
    ):

        incident_id = (
            plan.get(
                "incident_id"
            )
        )

        severity = (
            plan.get(
                "severity"
            )
        )

        risk_score = (
            plan.get(
                "risk_score"
            )
        )

        message = (
            "[SOC NOTIFICATION] "
            f"incident={incident_id} "
            f"severity={severity} "
            f"risk={risk_score}"
        )

        self.writer(
            message
        )

        return {
            "channel": "local",
            "status": "SUCCESS",
            "backend": "console",
            "incident_id": incident_id,
        }
