class ControllerStub:

    def __init__(self):
        self.calls = 0

    def build_dashboard(self):
        self.calls += 1
        return "DASHBOARD"


class LiveStub:

    def __init__(self):
        self.started = 0
        self.stopped = 0
        self.updates = []

    def start(self, refresh=False):
        self.started += 1

    def update(
        self,
        renderable,
        refresh=False,
    ):
        self.updates.append(
            (
                renderable,
                refresh,
            )
        )

    def stop(self):
        self.stopped += 1


def test_persistent_session_starts_with_current_dashboard():
    from engine.presentation.persistent_monitor_session import (
        PersistentMonitorSession,
    )

    controller = ControllerStub()
    live = LiveStub()

    session = PersistentMonitorSession(
        controller=controller,
        live=live,
    )

    session.start()

    assert controller.calls == 1
    assert live.started == 1
    assert live.updates == [
        (
            "DASHBOARD",
            True,
        )
    ]


def test_persistent_session_refreshes_dashboard():
    from engine.presentation.persistent_monitor_session import (
        PersistentMonitorSession,
    )

    controller = ControllerStub()
    live = LiveStub()

    session = PersistentMonitorSession(
        controller=controller,
        live=live,
    )

    session.refresh()

    assert controller.calls == 1
    assert live.updates == [
        (
            "DASHBOARD",
            True,
        )
    ]


def test_persistent_session_stops_live_display():
    from engine.presentation.persistent_monitor_session import (
        PersistentMonitorSession,
    )

    live = LiveStub()

    session = PersistentMonitorSession(
        controller=ControllerStub(),
        live=live,
    )

    session.stop()

    assert live.stopped == 1


def test_persistent_session_exposes_no_domain_write_methods():
    from engine.presentation.persistent_monitor_session import (
        PersistentMonitorSession,
    )

    public = {
        name
        for name in dir(PersistentMonitorSession)
        if not name.startswith("_")
    }

    forbidden = {
        "save",
        "write",
        "delete",
        "remove",
        "send",
        "execute",
        "block",
        "release",
        "acknowledge",
    }

    assert public & forbidden == set()

def test_build_persistent_monitor_session_shares_renderer_console():
    from rich.console import Console

    from engine.presentation.persistent_monitor_session import (
        build_persistent_monitor_session,
    )

    class Renderer:

        def __init__(self):
            self.console = Console()

    class Controller:

        def __init__(self):
            self.renderer = Renderer()

    controller = Controller()

    session = build_persistent_monitor_session(
        controller
    )

    assert (
        session.live.console
        is controller.renderer.console
    )


def test_real_live_does_not_redirect_standard_streams():
    from rich.console import Console

    from engine.presentation.persistent_monitor_session import (
        build_persistent_monitor_session,
    )

    class Renderer:

        def __init__(self):
            self.console = Console()

    class Controller:

        def __init__(self):
            self.renderer = Renderer()

    session = build_persistent_monitor_session(
        Controller()
    )

    assert session.live._redirect_stdout is False
    assert session.live._redirect_stderr is False


def test_real_live_uses_manual_refresh():
    from rich.console import Console

    from engine.presentation.persistent_monitor_session import (
        build_persistent_monitor_session,
    )

    class Renderer:

        def __init__(self):
            self.console = Console()

    class Controller:

        def __init__(self):
            self.renderer = Renderer()

    session = build_persistent_monitor_session(
        Controller()
    )

    assert session.live.auto_refresh is False

def test_session_starts_live_before_initial_dashboard_refresh():

    from engine.presentation.persistent_monitor_session import (
        PersistentMonitorSession,
    )

    events = []

    class Controller:

        def build_dashboard(self):
            events.append(
                "build"
            )
            return "DASHBOARD"

    class Live:

        def start(
            self,
            refresh=False,
        ):
            events.append(
                (
                    "start",
                    refresh,
                )
            )

        def update(
            self,
            dashboard,
            refresh=False,
        ):
            events.append(
                (
                    "update",
                    dashboard,
                    refresh,
                )
            )

        def stop(self):
            pass

    session = PersistentMonitorSession(
        controller=Controller(),
        live=Live(),
    )

    session.start()

    assert events == [
        "build",
        (
            "start",
            False,
        ),
        (
            "update",
            "DASHBOARD",
            True,
        ),
    ]

def test_command_output_captures_and_restores_streams():
    import sys

    from engine.presentation.persistent_monitor_session import (
        PersistentMonitorSession,
    )

    class Controller:
        pass

    class Live:
        console = object()

    session = PersistentMonitorSession(
        controller=Controller(),
        live=Live(),
    )

    original_stdout = sys.stdout
    original_stderr = sys.stderr

    with session.command_output():
        assert sys.stdout is not original_stdout
        assert sys.stderr is not original_stderr

        print(
            "CAPTURED"
        )

    assert sys.stdout is original_stdout
    assert sys.stderr is original_stderr
    assert session.command_output_text == "CAPTURED"


def test_command_output_does_not_write_directly_to_live_console():
    from engine.presentation.persistent_monitor_session import (
        PersistentMonitorSession,
    )

    class Controller:
        pass

    class LiveConsole:

        def print(
            self,
            _output,
        ):
            raise AssertionError(
                "command output must remain buffered"
            )

    class Live:
        console = LiveConsole()

    session = PersistentMonitorSession(
        controller=Controller(),
        live=Live(),
    )

    with session.command_output():
        print(
            "BUFFER ONLY"
        )

    assert session.command_output_text == "BUFFER ONLY"


def test_persistent_monitor_factory_uses_alternate_screen(
    monkeypatch,
):

    import engine.presentation.persistent_monitor_session as module

    captured = {}

    class Renderer:

        console = object()

    class Controller:

        renderer = Renderer()

    class FakeLive:

        def __init__(
            self,
            **kwargs,
        ):
            captured.update(
                kwargs
            )

    monkeypatch.setattr(
        module,
        "Live",
        FakeLive,
    )

    module.build_persistent_monitor_session(
        Controller()
    )

    assert captured["screen"] is True


def test_session_refresh_passes_captured_command_output_to_dashboard():
    import sys

    from engine.presentation.persistent_monitor_session import (
        PersistentMonitorSession,
    )

    events = []

    class Console:

        def __enter__(self):
            return self

        def __exit__(
            self,
            exc_type,
            exc,
            tb,
        ):
            return False

        def print(
            self,
            output,
        ):
            events.append(
                (
                    "console_print",
                    str(output),
                )
            )

    class Controller:

        def build_dashboard(
            self,
            command_output=None,
        ):
            events.append(
                (
                    "build",
                    command_output,
                )
            )
            return "DASHBOARD"

    class Live:

        def __init__(self):
            self.console = Console()

        def update(
            self,
            dashboard,
            refresh=False,
        ):
            events.append(
                (
                    "update",
                    dashboard,
                    refresh,
                )
            )

    session = PersistentMonitorSession(
        controller=Controller(),
        live=Live(),
    )

    original_stdout = sys.stdout

    with session.command_output():
        print(
            "HEALTH RESULT"
        )

    assert sys.stdout is original_stdout

    session.refresh()

    assert (
        "build",
        "HEALTH RESULT",
    ) in events


def test_session_command_output_replaces_previous_command_output():
    import sys

    from engine.presentation.persistent_monitor_session import (
        PersistentMonitorSession,
    )

    class Console:

        def __enter__(self):
            return self

        def __exit__(
            self,
            exc_type,
            exc,
            tb,
        ):
            return False

        def print(
            self,
            _output,
        ):
            pass

    class Controller:

        def __init__(self):
            self.outputs = []

        def build_dashboard(
            self,
            command_output=None,
        ):
            self.outputs.append(
                command_output
            )
            return "DASHBOARD"

    class Live:

        def __init__(self):
            self.console = Console()

        def update(
            self,
            _dashboard,
            refresh=False,
        ):
            pass

    controller = Controller()

    session = PersistentMonitorSession(
        controller=controller,
        live=Live(),
    )

    with session.command_output():
        print(
            "FIRST"
        )

    with session.command_output():
        print(
            "SECOND"
        )

    session.refresh()

    assert controller.outputs[-1] == "SECOND"
