import io
import sys
from contextlib import contextmanager

from rich.console import Console
from rich.live import Live


class PersistentMonitorSession:

    def __init__(
        self,
        controller,
        live,
    ):
        self.controller = controller
        self.live = live
        self.command_output_text = None

    def start(self):
        dashboard = self._build_dashboard()

        self.live.start(
            refresh=False
        )

        self.live.update(
            dashboard,
            refresh=True,
        )

    def refresh(self):
        dashboard = self._build_dashboard()

        self.live.update(
            dashboard,
            refresh=True,
        )

    def stop(self):
        self.live.stop()

    def _build_dashboard(self):
        if self.command_output_text is None:
            return self.controller.build_dashboard()

        return self.controller.build_dashboard(
            command_output=self.command_output_text
        )

    @contextmanager
    def command_output(self):
        original_stdout = sys.stdout
        original_stderr = sys.stderr

        buffer = io.StringIO()

        console_size = getattr(
            self.live.console,
            "size",
            None,
        )

        capture_width = getattr(
            console_size,
            "width",
            120,
        )

        capture_console = Console(
            file=buffer,
            force_terminal=False,
            color_system=None,
            width=capture_width,
        )

        try:
            sys.stdout = capture_console.file
            sys.stderr = capture_console.file

            yield

        finally:
            sys.stdout = original_stdout
            sys.stderr = original_stderr

            captured = buffer.getvalue().strip()

            self.command_output_text = (
                captured
                if captured
                else None
            )

def build_persistent_monitor_session(
    controller,
):
    live = Live(
        console=controller.renderer.console,
        screen=True,
        auto_refresh=False,
        redirect_stdout=False,
        redirect_stderr=False,
        transient=False,
    )

    return PersistentMonitorSession(
        controller=controller,
        live=live,
    )
