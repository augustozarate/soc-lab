from engine.orchestration.runtime.soc_runtime import (
    SOCRuntime,
)


class Reader:

    position = 0
    filepath = "unused"

    def read_new_events(self):

        return []


class Maintenance:

    def __init__(
        self,
        name,
        order,
    ):

        self.name = name
        self.order = order
        self.calls = 0
        self.callback = None

    def sweep(self):

        self.calls += 1

        self.order.append(
            self.name
        )

        if self.callback:
            self.callback()

        return []


class Container:

    def __init__(
        self,
        order,
    ):

        self.reader = Reader()

        self.response_block_expiration = (
            Maintenance(
                "expiration",
                order,
            )
        )

        self.response_block_reconciliation = (
            Maintenance(
                "reconciliation",
                order,
            )
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


def runtime_for(
    container,
    logger,
):

    runtime = SOCRuntime(
        container=container,
        cli=CLI(),
        watcher=Watcher(),
        scheduler=Scheduler(),
        worker_pool=WorkerPool(),
        logger=logger,
    )

    runtime._update_runtime_gauges = (
        lambda: None
    )

    return runtime


def test_runtime_orders_expiration_before_reconciliation(
    monkeypatch,
):

    order = []

    container = Container(
        order
    )

    runtime = runtime_for(
        container,
        lambda message: None,
    )


    container.response_block_reconciliation.callback = (
        lambda: setattr(
            runtime,
            "running",
            False,
        )
    )


    monkeypatch.setattr(
        "engine.orchestration.runtime."
        "soc_runtime.time.sleep",
        lambda seconds: None,
    )


    runtime.running = True

    runtime._event_loop()


    assert order == [
        "expiration",
        "reconciliation",
    ]

    assert (
        container
        .response_block_expiration
        .calls
        == 1
    )

    assert (
        container
        .response_block_reconciliation
        .calls
        == 1
    )


def test_reconciliation_runs_without_events(
    monkeypatch,
):

    order = []

    container = Container(
        order
    )

    runtime = runtime_for(
        container,
        lambda message: None,
    )


    container.response_block_reconciliation.callback = (
        lambda: setattr(
            runtime,
            "running",
            False,
        )
    )


    monkeypatch.setattr(
        "engine.orchestration.runtime."
        "soc_runtime.time.sleep",
        lambda seconds: None,
    )


    runtime.running = True

    runtime._event_loop()


    assert (
        container
        .response_block_reconciliation
        .calls
        == 1
    )


def test_reconciliation_failure_is_logged(
    monkeypatch,
):

    order = []

    container = Container(
        order
    )


    class FailingReconciliation:

        def __init__(self):

            self.calls = 0

        def sweep(self):

            self.calls += 1

            raise RuntimeError(
                "reconciliation unavailable"
            )


    reconciliation = (
        FailingReconciliation()
    )

    container.response_block_reconciliation = (
        reconciliation
    )


    messages = []

    runtime = runtime_for(
        container,
        messages.append,
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


    assert reconciliation.calls == 1

    assert any(
        "reconciliation unavailable"
        in message
        for message in messages
    )


def test_expiration_failure_prevents_same_cycle_reconciliation(
    monkeypatch,
):

    order = []

    container = Container(
        order
    )


    class FailingExpiration:

        def __init__(self):

            self.calls = 0

        def sweep(self):

            self.calls += 1

            order.append(
                "expiration"
            )

            raise RuntimeError(
                "expiration unavailable"
            )


    expiration = FailingExpiration()

    container.response_block_expiration = (
        expiration
    )


    messages = []

    runtime = runtime_for(
        container,
        messages.append,
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


    assert expiration.calls == 1

    assert (
        container
        .response_block_reconciliation
        .calls
        == 0
    )

    assert any(
        "expiration unavailable"
        in message
        for message in messages
    )
