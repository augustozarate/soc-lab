from engine.orchestration.runtime.soc_runtime import (
    SOCRuntime,
)


class Reader:

    position = 0
    filepath = "unused"

    def read_new_events(self):

        return []


class Expiration:

    def __init__(self):

        self.calls = 0
        self.on_sweep = None

    def sweep(self):

        self.calls += 1

        if self.on_sweep:
            self.on_sweep()

        return []


class Container:

    def __init__(self):

        self.reader = Reader()

        self.response_block_expiration = (
            Expiration()
        )

        self.event_cache = []


class Scheduler:

    def depth(self):
        return 0


class WorkerPool:
    pass


class Watcher:
    pass


class CLI:
    pass


def test_runtime_runs_expiration_without_events(
    monkeypatch,
):

    container = Container()

    runtime = SOCRuntime(
        container=container,
        cli=CLI(),
        watcher=Watcher(),
        scheduler=Scheduler(),
        worker_pool=WorkerPool(),
        logger=lambda message: None,
    )

    runtime._update_runtime_gauges = (
        lambda: None
    )

    monkeypatch.setattr(
        "engine.orchestration.runtime."
        "soc_runtime.time.sleep",
        lambda seconds: None,
    )

    container.response_block_expiration.on_sweep = (
        lambda: setattr(
            runtime,
            "running",
            False,
        )
    )

    runtime.running = True

    runtime._event_loop()

    assert (
        container
        .response_block_expiration
        .calls
        == 1
    )


def test_runtime_logs_top_level_expiration_failure(
    monkeypatch,
):

    class FailingExpiration:

        def __init__(self):
            self.calls = 0

        def sweep(self):

            self.calls += 1

            raise RuntimeError(
                "expiration database unavailable"
            )

    container = Container()

    container.response_block_expiration = (
        FailingExpiration()
    )

    messages = []

    runtime = SOCRuntime(
        container=container,
        cli=CLI(),
        watcher=Watcher(),
        scheduler=Scheduler(),
        worker_pool=WorkerPool(),
        logger=messages.append,
    )

    runtime._update_runtime_gauges = (
        lambda: None
    )

    def stop_after_sleep(
        seconds,
    ):

        runtime.running = False

    monkeypatch.setattr(
        "engine.orchestration.runtime."
        "soc_runtime.time.sleep",
        stop_after_sleep,
    )

    runtime.running = True

    runtime._event_loop()

    assert (
        container
        .response_block_expiration
        .calls
        == 1
    )

    assert any(
        "expiration database unavailable"
        in message
        for message in messages
    )
