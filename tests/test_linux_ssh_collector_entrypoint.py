import importlib.util
from pathlib import Path


ENTRYPOINT = (
    Path(__file__).resolve().parents[1]
    / "collectors"
    / "linux_ssh_collector.py"
)


def _load_entrypoint():

    spec = importlib.util.spec_from_file_location(
        "linux_ssh_collector_entrypoint",
        ENTRYPOINT,
    )

    if spec is None or spec.loader is None:
        raise RuntimeError(
            "unable to load collector entrypoint"
        )

    module = importlib.util.module_from_spec(
        spec
    )

    spec.loader.exec_module(
        module
    )

    return module


def test_linux_collector_entrypoint_exists():

    assert ENTRYPOINT.exists()


def test_build_collector_uses_expected_project_paths(
    tmp_path,
):

    module = _load_entrypoint()

    collector = module.build_collector(
        project_root=tmp_path
    )

    assert collector.stream_path == (
        tmp_path
        / "logs"
        / "stream.jsonl"
    )

    assert collector.checkpoint.path == (
        tmp_path
        / "data"
        / "linux_ssh_collector_checkpoint.json"
    )

    assert collector.source.unit == "ssh"


class _FakeCollector:

    def __init__(
        self,
        emitted_values=None,
    ):
        self.emitted_values = list(
            emitted_values or [0]
        )

        self.calls = 0

    def run_once(self):

        self.calls += 1

        if self.emitted_values:
            return self.emitted_values.pop(0)

        return 0


def test_run_collector_once_calls_exactly_once():

    module = _load_entrypoint()

    collector = _FakeCollector(
        emitted_values=[2]
    )

    result = module.run_collector(
        collector,
        once=True,
        interval=0,
        sleep=lambda _: None,
    )

    assert result == 2
    assert collector.calls == 1


def test_run_collector_loop_sleeps_between_cycles():

    module = _load_entrypoint()

    collector = _FakeCollector(
        emitted_values=[
            1,
            0,
        ]
    )

    sleeps = []

    class _StopLoop(Exception):
        pass

    def fake_sleep(
        seconds,
    ):

        sleeps.append(
            seconds
        )

        if len(sleeps) == 2:
            raise _StopLoop()

    try:

        module.run_collector(
            collector,
            once=False,
            interval=2.5,
            sleep=fake_sleep,
        )

    except _StopLoop:
        pass

    assert collector.calls == 2

    assert sleeps == [
        2.5,
        2.5,
    ]


def test_run_collector_rejects_negative_interval():

    module = _load_entrypoint()

    collector = _FakeCollector()

    try:

        module.run_collector(
            collector,
            once=True,
            interval=-1,
            sleep=lambda _: None,
        )

    except ValueError:
        pass

    else:
        raise AssertionError(
            "negative interval must be rejected"
        )


def test_parser_accepts_once_and_interval():

    module = _load_entrypoint()

    parser = module.build_parser()

    args = parser.parse_args(
        [
            "--once",
            "--interval",
            "1.5",
        ]
    )

    assert args.once is True
    assert args.interval == 1.5
