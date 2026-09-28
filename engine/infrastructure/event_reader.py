import json
import os
import tempfile


class EventReader:

    def __init__(
        self,
        filepath,
        checkpoint_file
    ):

        self.filepath = filepath
        self.checkpoint_file = checkpoint_file

        self.position = 0
        self.file_identity = None

        self.pending_position = None
        self.pending_identity = None

        self._load_checkpoint()

    # =====================================

    def _load_checkpoint(self):

        if not os.path.exists(
            self.checkpoint_file
        ):
            return

        try:

            with open(
                self.checkpoint_file,
                "r",
                encoding="utf-8"
            ) as f:

                checkpoint = json.load(f)

            self.position = int(
                checkpoint.get(
                    "position",
                    0
                )
            )

            device = checkpoint.get(
                "device"
            )

            inode = checkpoint.get(
                "inode"
            )

            if (
                device is not None
                and inode is not None
            ):
                self.file_identity = (
                    device,
                    inode
                )

        except (
            OSError,
            ValueError,
            TypeError,
            json.JSONDecodeError
        ):

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

            pending_position = (
                f.tell()
            )

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

        self.pending_position = (
            pending_position
        )

        self.pending_identity = (
            identity
        )

        return events

    # =====================================

    def commit(self):

        if self.pending_position is None:
            return

        self.position = (
            self.pending_position
        )

        self.file_identity = (
            self.pending_identity
        )

        self._save_checkpoint()

        self.pending_position = None
        self.pending_identity = None

    # =====================================

    def _save_checkpoint(self):

        directory = os.path.dirname(
            self.checkpoint_file
        )

        if directory:
            os.makedirs(
                directory,
                exist_ok=True
            )

        checkpoint = {
            "position": self.position,
            "device": (
                self.file_identity[0]
                if self.file_identity
                else None
            ),
            "inode": (
                self.file_identity[1]
                if self.file_identity
                else None
            )
        }

        fd, temp_path = tempfile.mkstemp(
            prefix=".event_reader_",
            suffix=".tmp",
            dir=directory or "."
        )

        try:

            with os.fdopen(
                fd,
                "w",
                encoding="utf-8"
            ) as f:

                json.dump(
                    checkpoint,
                    f,
                    ensure_ascii=False,
                    indent=2
                )

                f.flush()
                os.fsync(
                    f.fileno()
                )

            os.replace(
                temp_path,
                self.checkpoint_file
            )

        except Exception:

            try:
                os.unlink(
                    temp_path
                )
            except FileNotFoundError:
                pass

            raise
