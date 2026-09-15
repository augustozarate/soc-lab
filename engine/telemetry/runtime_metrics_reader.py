import json


class RuntimeMetricsReader:

    def __init__(
        self,
        path
    ):

        self.path = path

    # =====================================

    def read(self):

        try:

            with open(
                self.path,
                "r",
                encoding="utf-8"
            ) as f:

                snapshot = json.load(
                    f
                )

        except (
            FileNotFoundError,
            json.JSONDecodeError,
            OSError
        ):

            return None

        if not isinstance(
            snapshot,
            dict
        ):
            return None

        return snapshot
