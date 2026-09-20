from engine.services.action_registry import (
    ActionRegistry
)

from engine.cli.console_io import (
    safe_print
)


class ResponseEngine:

    def __init__(
        self,
        response_mode="simulate",
        firewall_backend=None,
        safety_policy=None,
    ):

        if response_mode not in {
            "simulate",
            "enforce",
        }:
            raise ValueError(
                "response_mode must be "
                "'simulate' or 'enforce'"
            )

        self.response_mode = (
            response_mode
        )

        self.firewall_backend = (
            firewall_backend
        )

        self.safety_policy = (
            safety_policy
        )

        # Simulation-only compatibility state.
        # This is not an enforcement source
        # of truth.
        self.blocked_ips = set()

        self.registry = (
            ActionRegistry()
        )

        self._register_builtin_actions()

    # =========================================
    # ACTION REGISTRATION
    # =========================================

    def _register_builtin_actions(self):

        self.registry.register(
            "BLOCK_IP",
            self.block_ip
        )

        self.registry.register(
            "NOTIFY_SOC",
            self.notify_soc
        )

        self.registry.register(
            "ENABLE_MFA",
            self.enable_mfa
        )

        self.registry.register(
            "ISOLATE_HOST",
            self.isolate_host
        )

        self.registry.register(
            "COLLECT_FORENSICS",
            self.collect_forensics
        )

    # =========================================
    # EXECUTION
    # =========================================

    def execute(self, action):

        action_type = action.get(
            "type"
        )

        handler = self.registry.get(
            action_type
        )

        if not handler:

            action["status"] = "FAILED"
            action["error"] = (
                f"No handler found for "
                f"{action_type}"
            )

            return action

        try:

            result = handler(
                action
            )

            if result is None:
                result = action

            if (
                result.get("status")
                == "PENDING"
            ):

                result["status"] = (
                    "FAILED"
                )

                result["error"] = (
                    "Response handler returned "
                    "without a final status"
                )

            return result

        except Exception as exc:

            action["status"] = "FAILED"
            action["error"] = str(exc)

            return action

    # =========================================
    # BLOCK IP
    # =========================================

    def block_ip(self, action):

        ip = action.get(
            "target"
        )

        if not ip:

            action["status"] = "FAILED"
            action["error"] = (
                "Missing target IP"
            )

            return action

        if (
            self.safety_policy is not None
            and
            self.safety_policy.is_protected(
                ip
            )
        ):

            action["status"] = (
                "PROTECTED"
            )

            action["reason"] = (
                "Target is protected by "
                "response safety policy"
            )

            action["backend"] = (
                "safety_policy"
            )

            action["execution_mode"] = (
                "PROTECTED"
            )

            return action

        if self.response_mode == "simulate":

            if ip in self.blocked_ips:

                action["status"] = "SKIPPED"
                action["reason"] = (
                    "IP already simulated as blocked"
                )
                action["backend"] = (
                    "memory"
                )

                action["execution_mode"] = (
                    "SIMULATED"
                )

                return action

            self.blocked_ips.add(
                ip
            )

            safe_print(
                "[ACTION]",
                (
                    "Simulated block for IP "
                    f"{ip}"
                )
            )

            action["status"] = (
                "SIMULATED"
            )

            action["backend"] = (
                "memory"
            )

            action["execution_mode"] = (
                "SIMULATED"
            )

            return action

        if self.firewall_backend is None:

            raise RuntimeError(
                "Firewall backend is not "
                "configured"
            )

        backend_result = (
            self.firewall_backend.block(
                ip
            )
        )

        action["status"] = "SUCCESS"

        action["backend"] = (
            "windows_firewall"
        )

        action["execution_mode"] = (
            "ENFORCED"
        )

        action["backend_status"] = (
            backend_result.get(
                "status"
            )
        )

        action["rule_name"] = (
            backend_result.get(
                "rule_name"
            )
        )

        safe_print(
            "[ACTION]",
            (
                f"Blocked IP {ip} "
                "via Windows Firewall"
            )
        )

        return action


    # =========================================
    # NOTIFY SOC
    # =========================================

    def notify_soc(self, action):

        safe_print(
            "[ACTION]",
            "SOC Team notified"
        )

        action["status"] = "SUCCESS"

        action["execution_mode"] = (
            "LOCAL"
        )

        action["backend"] = (
            "console"
        )

        return action

    # =========================================
    # ENABLE MFA
    # =========================================

    def enable_mfa(self, action):

        target = action.get(
            "target"
        )

        safe_print(
            "[ACTION]",
            f"MFA requested for {target}"
        )

        # Simulated action
        action["status"] = "SUCCESS"

        action["execution_mode"] = (
            "SIMULATED"
        )

        action["backend"] = (
            "simulation"
        )

        return action

    # =========================================
    # ISOLATE HOST
    # =========================================

    def isolate_host(self, action):

        target = action.get(
            "target"
        )

        safe_print(
            "[ACTION]",
            f"Host isolation requested for {target}"
        )

        # Simulated action
        action["status"] = "SUCCESS"

        action["execution_mode"] = (
            "SIMULATED"
        )

        action["backend"] = (
            "simulation"
        )

        return action

    # =========================================
    # COLLECT FORENSICS
    # =========================================

    def collect_forensics(
        self,
        action
    ):

        target = action.get(
            "target"
        )

        safe_print(
            "[ACTION]",
            (
                "Forensic collection requested "
                f"for {target}"
            )
        )

        # Simulated action
        action["status"] = "SUCCESS"

        action["execution_mode"] = (
            "SIMULATED"
        )

        action["backend"] = (
            "simulation"
        )

        return action