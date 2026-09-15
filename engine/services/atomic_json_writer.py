import json
import os
import tempfile


class AtomicJsonWriter:

    def __init__(
        self,
        path,
        temp_prefix=".snapshot_"
    ):

        self.path = path
        self.temp_prefix = temp_prefix

    # =====================================

    def write(
        self,
        snapshot
    ):

        directory = os.path.dirname(
            self.path
        )

        if directory:

            os.makedirs(
                directory,
                exist_ok=True
            )

        fd, temp_path = (
            tempfile.mkstemp(
                prefix=self.temp_prefix,
                suffix=".json.tmp",
                dir=directory or "."
            )
        )

        try:

            with os.fdopen(
                fd,
                "w",
                encoding="utf-8"
            ) as f:

                json.dump(
                    snapshot,
                    f,
                    ensure_ascii=False,
                    indent=2
                )

                f.flush()

                os.fsync(
                    f.fileno()
                )

            os.replace(
                temp_path,
                self.path
            )

        except Exception:

            try:

                os.unlink(
                    temp_path
                )

            except FileNotFoundError:

                pass

            raise
