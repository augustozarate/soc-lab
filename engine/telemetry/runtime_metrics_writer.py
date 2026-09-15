from engine.services.atomic_json_writer import (
    AtomicJsonWriter
)


class RuntimeMetricsWriter(
    AtomicJsonWriter
):

    def __init__(
        self,
        path
    ):

        super().__init__(
            path=path,
            temp_prefix=".runtime_metrics_"
        )
