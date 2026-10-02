from engine.orchestration.runtime.soc_runtime import (
    SOCRuntime,
)


def test_event_loop_cli_exit_preserves_running_for_central_stop(
    monkeypatch,
):

    class CLI:

        def is_alive(self):
            return False

    class Reader:

        def __init__(self):
            self.read_calls = 0

        def read_new_events(self):
            self.read_calls += 1
            return []

    class NoOp:

        def sweep(self):
            pass

    class Container:

        def __init__(self):
            self.reader = Reader()
            self.response_block_expiration = NoOp()
            self.response_block_reconciliation = NoOp()

    runtime = SOCRuntime(
        container=Container(),
        cli=CLI(),
        watcher=object(),
        scheduler=None,
        worker_pool=object(),
        logger=lambda _message: None,
    )

    runtime.running = True

    def fail_sleep(_seconds):
        raise AssertionError(
            "event loop continued after CLI exit"
        )

    monkeypatch.setattr(
        "engine.orchestration.runtime.soc_runtime.time.sleep",
        fail_sleep,
    )

    runtime._event_loop()

    assert runtime.running is True
    assert runtime.container.reader.read_calls == 0


def test_start_cli_exit_executes_centralized_shutdown():

    events = []

    class CLI:

        def start_async(self):
            events.append(
                "cli-start"
            )

        def is_alive(self):
            return False

    class WorkerPool:

        def start(self):
            events.append(
                "workers-start"
            )

        def stop(self):
            events.append(
                "workers-stop"
            )

        def join(self):
            events.append(
                "workers-join"
            )

    class Watcher:

        def start_async(self):
            events.append(
                "watcher-start"
            )

        def stop(self):
            events.append(
                "watcher-stop"
            )

    class Reader:

        def read_new_events(self):
            raise AssertionError(
                "reader must not run after CLI exit"
            )

    class NoOp:

        def sweep(self):
            pass

    class Container:

        def __init__(self):
            self.reader = Reader()
            self.response_block_expiration = NoOp()
            self.response_block_reconciliation = NoOp()

    runtime = SOCRuntime(
        container=Container(),
        cli=CLI(),
        watcher=Watcher(),
        scheduler=None,
        worker_pool=WorkerPool(),
        logger=lambda message: events.append(
            message
        ),
    )

    runtime.start()

    assert runtime.running is False

    assert "workers-stop" in events
    assert "workers-join" in events
    assert "watcher-stop" in events
    assert "[RUNTIME] Shutdown complete" in events
