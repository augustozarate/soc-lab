from engine.services.action_registry import (
    ActionRegistry
)

from engine.cli.console_io import (
    safe_print
)


class ResponseEngine:

    def __init__(self):

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
                    "SUCCESS"
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

        if ip in self.blocked_ips:

            action["status"] = "SKIPPED"
            action["reason"] = (
                "IP already blocked"
            )

            return action

        self.blocked_ips.add(
            ip
        )

        safe_print(
            "[ACTION]",
            f"Blocked IP {ip}"
        )

        action["status"] = "SUCCESS"

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

        return action