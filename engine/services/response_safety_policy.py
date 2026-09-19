import ipaddress


class ResponseSafetyPolicy:

    def __init__(
        self,
        protected_ips=None,
    ):

        self.protected_ips = frozenset(
            self._normalize_protected_ip(
                value
            )
            for value in (
                protected_ips
                or ()
            )
        )

    @staticmethod
    def _normalize_protected_ip(
        value,
    ):

        if not isinstance(
            value,
            str,
        ):
            raise ValueError(
                "Protected IP must be a string"
            )

        candidate = value.strip()

        if not candidate:
            raise ValueError(
                "Protected IP cannot be empty"
            )

        try:

            address = (
                ipaddress.ip_address(
                    candidate
                )
            )

        except ValueError as exc:

            raise ValueError(
                "Invalid protected IP: "
                f"{candidate}"
            ) from exc

        if address.version != 4:

            raise ValueError(
                "Only IPv4 protected targets "
                "are supported"
            )

        return str(address)

    def is_protected(
        self,
        target,
    ):

        if not isinstance(
            target,
            str,
        ):
            return False

        candidate = target.strip()

        if not candidate:
            return False

        try:

            address = (
                ipaddress.ip_address(
                    candidate
                )
            )

        except ValueError:

            return False

        if address.version != 4:
            return False

        return (
            str(address)
            in self.protected_ips
        )
