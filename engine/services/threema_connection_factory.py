import stat
from pathlib import Path

from threema.gateway import Connection
from threema.gateway.key import Key


class ThreemaSecureConnectionFactory:

    MAX_KEY_FILE_BYTES = 4096

    def __init__(
        self,
        gateway_id,
        api_secret,
        private_key_file,
        connection_class=None,
    ):

        self.gateway_id = (
            self._validate_scalar(
                gateway_id,
                "Gateway ID",
            )
        )

        self.api_secret = (
            self._validate_scalar(
                api_secret,
                "API secret",
            )
        )

        self.private_key_file = Path(
            private_key_file
        ).expanduser()

        self.connection_class = (
            connection_class
            or Connection
        )

    # =========================================
    # PUBLIC
    # =========================================

    def build(
        self,
    ):

        private_key = (
            self._load_private_key()
        )

        try:

            return self.connection_class(
                identity=self.gateway_id,
                secret=self.api_secret,
                key=private_key,
                blocking=True,
            )

        except Exception:

            raise RuntimeError(
                "Unable to create secure "
                "Threema connection"
            ) from None

    # =========================================
    # CONFIG VALIDATION
    # =========================================

    def _validate_scalar(
        self,
        value,
        label,
    ):

        if not isinstance(
            value,
            str,
        ):

            raise TypeError(
                f"Threema {label} "
                "must be a string"
            )

        value = value.strip()

        if not value:

            raise ValueError(
                f"Threema {label} "
                "is required"
            )

        if (
            "\r" in value
            or "\n" in value
        ):

            raise ValueError(
                f"Threema {label} "
                "contains invalid characters"
            )

        return value

    # =========================================
    # PRIVATE KEY
    # =========================================

    def _load_private_key(
        self,
    ):

        path = self.private_key_file

        try:

            if path.is_symlink():

                raise ValueError(
                    "Threema private key file "
                    "must not be a symbolic link"
                )

            if not path.exists():

                raise ValueError(
                    "Threema private key file "
                    "does not exist"
                )

            if not path.is_file():

                raise ValueError(
                    "Threema private key path "
                    "must reference a regular file"
                )

            metadata = path.stat()

        except ValueError:

            raise

        except OSError:

            raise ValueError(
                "Unable to validate Threema "
                "private key file"
            ) from None

        mode = stat.S_IMODE(
            metadata.st_mode
        )

        if mode & 0o077:

            raise ValueError(
                "Threema private key file "
                "permissions are too broad"
            )

        if (
            metadata.st_size <= 0
            or metadata.st_size
            > self.MAX_KEY_FILE_BYTES
        ):

            raise ValueError(
                "Invalid Threema private "
                "key file"
            )

        try:

            with path.open(
                "r",
                encoding="utf-8",
            ) as handle:

                first_line = (
                    handle.readline(
                        self.MAX_KEY_FILE_BYTES
                        + 1
                    )
                    .strip()
                )

                extra = handle.read(
                    1
                )

        except (
            OSError,
            UnicodeError,
        ):

            raise ValueError(
                "Unable to read Threema "
                "private key file"
            ) from None

        if (
            not first_line
            or extra
        ):

            raise ValueError(
                "Invalid Threema private "
                "key file"
            )

        try:

            return Key.decode(
                first_line,
                Key.Type.private,
            )

        except Exception:

            raise ValueError(
                "Invalid Threema private key"
            ) from None
