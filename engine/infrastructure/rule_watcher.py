import os
import time
import hashlib
import threading

from engine.cli.console_io import safe_print


class RuleWatcher:

    def __init__(
        self,
        path,
        reload_callback
    ):

        self.path = path
        self.reload_callback = reload_callback

        self.last_hash = None

        self._stop_event = (
            threading.Event()
        )

        self._thread = None

    # =====================================

    def compute_hash(self):

        sha = hashlib.sha256()

        for root, _, files in os.walk(
            self.path
        ):

            for filename in sorted(files):

                if not filename.endswith(".yml"):
                    continue

                filepath = os.path.join(
                    root,
                    filename
                )

                try:

                    with open(
                        filepath,
                        "rb"
                    ) as fh:

                        sha.update(
                            fh.read()
                        )

                except OSError as error:

                    safe_print(
                        "[RULE WATCHER] "
                        f"Unable to read "
                        f"{filepath}: {error}"
                    )

        return sha.hexdigest()

    # =====================================

    def start(self):

        self._stop_event.clear()

        safe_print(
            "[RULE WATCHER] Started"
        )

        while not self._stop_event.is_set():

            try:

                current_hash = (
                    self.compute_hash()
                )

                if (
                    self.last_hash
                    and
                    current_hash
                    != self.last_hash
                ):

                    safe_print(
                        "[RULE WATCHER] "
                        "Change detected — "
                        "reloading rules"
                    )

                    self.reload_callback()

                self.last_hash = (
                    current_hash
                )

            except Exception as error:

                safe_print(
                    "[RULE WATCHER] "
                    f"Error: {error}"
                )

            self._stop_event.wait(
                3
            )

        safe_print(
            "[RULE WATCHER] Stopped"
        )

    # =====================================

    def start_async(self):

        if (
            self._thread
            and self._thread.is_alive()
        ):
            return

        self._thread = threading.Thread(
            target=self.start,
            daemon=True,
            name="soc-rule-watcher"
        )

        self._thread.start()

    # =====================================

    def stop(self):

        self._stop_event.set()

        if (
            self._thread
            and self._thread.is_alive()
        ):

            self._thread.join(
                timeout=4
            )

    # =====================================

    def is_alive(self):

        return bool(
            self._thread
            and self._thread.is_alive()
        )