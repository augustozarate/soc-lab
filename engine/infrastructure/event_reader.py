import json
import os


class EventReader:

    def __init__(
        self,
        filepath
    ):

        self.filepath = filepath
        self.position = 0
        self.file_identity = None

    # =====================================

    def read_new_events(self):

        if not os.path.exists(
            self.filepath
        ):
            return []

        try:

            stat = os.stat(
                self.filepath
            )

        except OSError:

            return []

        identity = (
            stat.st_dev,
            stat.st_ino
        )

        # File replaced / rotated
        if (
            self.file_identity is not None
            and identity != self.file_identity
        ):

            self.position = 0

        self.file_identity = identity

        # File truncated
        if stat.st_size < self.position:

            self.position = 0

        events = []

        with open(
            self.filepath,
            "r",
            encoding="utf-8"
        ) as f:

            f.seek(
                self.position
            )

            lines = f.readlines()

            self.position = f.tell()

        for line in lines:

            line = line.strip()

            if not line:
                continue

            try:

                events.append(
                    json.loads(line)
                )

            except json.JSONDecodeError:

                print(
                    "[READER] Bad JSON skipped"
                )

        return events