class NotificationSubscriber:

    def __init__(
        self,
        policy,
        service,
    ):

        self.policy = policy
        self.service = service

    def on_incident_persisted(
        self,
        payload,
    ):

        if not isinstance(
            payload,
            dict,
        ):

            return []

        incident = payload.get(
            "incident"
        )

        if not isinstance(
            incident,
            dict,
        ):

            return []

        plan = self.policy.evaluate(
            incident,
            event_type=(
                "incident_persisted"
            ),
        )

        if plan is None:

            return []

        return self.service.dispatch(
            plan,
            incident,
        )
