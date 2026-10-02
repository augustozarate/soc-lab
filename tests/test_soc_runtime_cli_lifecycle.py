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


def test_event_loop_refreshes_monitor_once_after_committed_event_batch(
    monkeypatch,
):

    events_seen = []

    class CLI:

        def __init__(self):
            self.alive_calls = 0
            self.refresh_calls = 0

        def is_alive(self):
            self.alive_calls += 1
            return self.alive_calls == 1

        def refresh_monitor(self):
            self.refresh_calls += 1
            events_seen.append(
                "refresh"
            )

    class Reader:

        def __init__(self):
            self.position = 0
            self.filepath = __file__
            self.commit_calls = 0

        def read_new_events(self):
            return [
                {
                    "id": "LAB47B-REFRESH-001",
                }
            ]

        def commit(self):
            self.commit_calls += 1
            events_seen.append(
                "commit"
            )

    class Detector:

        def evaluate(self, _event):
            return []

    class BehaviorEngine:

        def analyze(self, _event):
            return []

    class RuntimeMetricsWriter:

        def write(self, _snapshot):
            pass

    class Sweep:

        def sweep(self):
            pass

    class EventCache(list):
        pass

    class Scheduler:

        def depth(self):
            return 0

    class Container:

        def __init__(self):
            self.reader = Reader()
            self.detector = Detector()
            self.behavior_engine = BehaviorEngine()
            self.event_cache = EventCache()
            self.runtime_metrics_writer = (
                RuntimeMetricsWriter()
            )
            self.response_block_expiration = Sweep()
            self.response_block_reconciliation = Sweep()

    cli = CLI()

    runtime = SOCRuntime(
        container=Container(),
        cli=cli,
        watcher=object(),
        scheduler=Scheduler(),
        worker_pool=object(),
        logger=lambda _message: None,
    )

    runtime.running = True

    monkeypatch.setattr(
        runtime,
        "_process_event",
        lambda _event: [],
    )

    monkeypatch.setattr(
        "engine.orchestration.runtime.soc_runtime.time.sleep",
        lambda _seconds: None,
    )

    runtime._event_loop()

    assert runtime.container.reader.commit_calls == 1
    assert cli.refresh_calls == 1

    assert events_seen == [
        "commit",
        "refresh",
    ]


def test_event_loop_does_not_refresh_monitor_for_empty_batch(
    monkeypatch,
):

    class CLI:

        def __init__(self):
            self.alive_calls = 0
            self.refresh_calls = 0

        def is_alive(self):
            self.alive_calls += 1
            return self.alive_calls == 1

        def refresh_monitor(self):
            self.refresh_calls += 1

    class Reader:

        def __init__(self):
            self.position = 0
            self.filepath = __file__

        def read_new_events(self):
            return []

    class RuntimeMetricsWriter:

        def write(self, _snapshot):
            pass

    class Sweep:

        def sweep(self):
            pass

    class Scheduler:

        def depth(self):
            return 0

    class Container:

        def __init__(self):
            self.reader = Reader()
            self.runtime_metrics_writer = (
                RuntimeMetricsWriter()
            )
            self.response_block_expiration = Sweep()
            self.response_block_reconciliation = Sweep()

    cli = CLI()

    runtime = SOCRuntime(
        container=Container(),
        cli=cli,
        watcher=object(),
        scheduler=Scheduler(),
        worker_pool=object(),
        logger=lambda _message: None,
    )

    runtime.running = True

    monkeypatch.setattr(
        "engine.orchestration.runtime.soc_runtime.time.sleep",
        lambda _seconds: None,
    )

    runtime._event_loop()

    assert cli.refresh_calls == 0
