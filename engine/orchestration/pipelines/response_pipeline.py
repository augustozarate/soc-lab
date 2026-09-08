class ResponsePipeline:

    def __init__(
        self,
        response_policy_engine,
        response_engine,
        soar,
        case_manager,
        event_bus
    ):

        self.response_policy_engine = response_policy_engine
        self.response_engine = response_engine
        self.soar = soar
        self.case_manager = case_manager
        self.event_bus = event_bus

    def run(self, context):

        incident = context["incident"]

        executed_actions = []

        incident.setdefault(
            "response_actions",
            []
        )

        # =====================================
        # RESPONSE POLICY
        # =====================================

        actions = self.response_policy_engine.evaluate(
            incident
        )

        # =====================================
        # RESPONSE EXECUTION
        # =====================================

        for action in actions:

            result = self.response_engine.execute(
                action
            )

            incident["response_actions"].append(
                result
            )

            executed_actions.append(
                result
            )

        # =====================================
        # SOAR
        # =====================================

        soar_actions = self.soar.evaluate(
            incident
        )

        for action in soar_actions:

            incident["response_actions"].append(
                action
            )

            executed_actions.append(
                action
            )

        # =====================================
        # CASE MANAGEMENT
        # =====================================

        self._auto_create_case(
            incident
        )

        # =====================================
        # EVENT
        # =====================================

        self.event_bus.emit(
            "response_executed",
            {
                "incident": incident,
                "actions": executed_actions
            }
        )

        return True

    def _auto_create_case(
        self,
        incident
    ):

        if incident.get(
            "risk_score",
            0
        ) < 80:

            return

        if incident.get(
            "case_created"
        ):

            return

        case_id = (
            self.case_manager.create_case(
                incident
            )
        )

        incident["case_created"] = True
        incident["case_id"] = case_id