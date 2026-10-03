import hashlib
import ipaddress
import json
import os
import re
import tempfile
import subprocess
from pathlib import Path
from datetime import datetime, timezone


_INVALID_USER_PATTERN = re.compile(
    r"^Failed password for invalid user "
    r"(?P<username>\S+) "
    r"from (?P<ip>\S+) "
    r"port (?P<port>\d+) ssh2$"
)

_EXISTING_USER_PATTERN = re.compile(
    r"^Failed password for "
    r"(?P<username>\S+) "
    r"from (?P<ip>\S+) "
    r"port (?P<port>\d+) ssh2$"
)


class JournalSource:

    def __init__(
        self,
        runner=None,
        unit="ssh",
    ):

        self.runner = (
            runner
            if runner is not None
            else subprocess.run
        )

        self.unit = unit

    def read(
        self,
        after_cursor=None,
    ):

        if after_cursor is not None:

            if not isinstance(
                after_cursor,
                str,
            ):
                raise ValueError(
                    "after_cursor must be a non-empty string"
                )

            if not after_cursor.strip():
                raise ValueError(
                    "after_cursor must be a non-empty string"
                )

        command = [
            "journalctl",
            "-u",
            self.unit,
            "-o",
            "json",
            "--no-pager",
        ]

        if after_cursor is not None:
            command.extend(
                [
                    "--after-cursor",
                    after_cursor,
                ]
            )

        result = self.runner(
            command,
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode != 0:
            raise RuntimeError(
                "journalctl read failed "
                f"with status {result.returncode}"
            )

        entries = []

        for raw in (
            result.stdout or ""
        ).splitlines():

            raw = raw.strip()

            if not raw:
                continue

            try:
                entry = json.loads(
                    raw
                )
            except json.JSONDecodeError:
                continue

            if not isinstance(
                entry,
                dict,
            ):
                continue

            entries.append(
                entry
            )

        return entries

    def latest_cursor(self):

        command = [
            "journalctl",
            "-u",
            self.unit,
            "-n",
            "1",
            "-o",
            "json",
            "--no-pager",
        ]

        result = self.runner(
            command,
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode != 0:
            raise RuntimeError(
                "journalctl baseline failed "
                f"with status {result.returncode}"
            )

        lines = (
            result.stdout or ""
        ).splitlines()

        for raw in reversed(
            lines
        ):

            raw = raw.strip()

            if not raw:
                continue

            try:
                entry = json.loads(
                    raw
                )
            except json.JSONDecodeError:
                continue

            if not isinstance(
                entry,
                dict,
            ):
                continue

            cursor = entry.get(
                "__CURSOR"
            )

            if not isinstance(
                cursor,
                str,
            ):
                return None

            if not cursor.strip():
                return None

            return cursor

        return None


class JournalCursorCheckpoint:

    def __init__(
        self,
        path,
    ):

        self.path = Path(
            path
        )

    def is_initialized(self):

        if not self.path.exists():
            return False

        try:

            data = json.loads(
                self.path.read_text(
                    encoding="utf-8"
                )
            )

        except (
            OSError,
            json.JSONDecodeError,
            TypeError,
        ):
            return False

        if not isinstance(
            data,
            dict,
        ):
            return False

        cursor = data.get(
            "cursor"
        )

        if isinstance(
            cursor,
            str,
        ) and cursor.strip():
            return True

        return (
            data.get(
                "initialized"
            )
            is True
            and cursor is None
        )

    def mark_initialized_empty(self):

        directory = (
            self.path.parent
        )

        directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        fd, temp_path = tempfile.mkstemp(
            prefix=".linux_ssh_checkpoint_",
            suffix=".tmp",
            dir=str(
                directory
            ),
        )

        try:

            with os.fdopen(
                fd,
                "w",
                encoding="utf-8",
            ) as handle:

                json.dump(
                    {
                        "cursor": None,
                        "initialized": True,
                    },
                    handle,
                    ensure_ascii=False,
                    indent=2,
                )

                handle.flush()

                os.fsync(
                    handle.fileno()
                )

            os.replace(
                temp_path,
                self.path,
            )

        except Exception:

            try:
                os.unlink(
                    temp_path
                )
            except FileNotFoundError:
                pass

            raise

    def load(self):

        if not self.path.exists():
            return None

        try:

            data = json.loads(
                self.path.read_text(
                    encoding="utf-8"
                )
            )

        except (
            OSError,
            json.JSONDecodeError,
            TypeError,
        ):
            return None

        cursor = data.get(
            "cursor"
        )

        if not isinstance(
            cursor,
            str,
        ):
            return None

        if not cursor.strip():
            return None

        return cursor

    def save(
        self,
        cursor,
    ):

        if not isinstance(
            cursor,
            str,
        ):
            raise ValueError(
                "cursor must be a non-empty string"
            )

        if not cursor.strip():
            raise ValueError(
                "cursor must be a non-empty string"
            )

        directory = (
            self.path.parent
        )

        directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        fd, temp_path = tempfile.mkstemp(
            prefix=".linux_ssh_checkpoint_",
            suffix=".tmp",
            dir=str(
                directory
            ),
        )

        try:

            with os.fdopen(
                fd,
                "w",
                encoding="utf-8",
            ) as handle:

                json.dump(
                    {
                        "cursor": cursor,
                    },
                    handle,
                    ensure_ascii=False,
                    indent=2,
                )

                handle.flush()
                os.fsync(
                    handle.fileno()
                )

            os.replace(
                temp_path,
                self.path,
            )

        except Exception:

            try:
                os.unlink(
                    temp_path
                )
            except FileNotFoundError:
                pass

            raise


class LinuxSSHCollector:

    def __init__(
        self,
        source,
        checkpoint,
        stream_path,
    ):

        self.source = source
        self.checkpoint = checkpoint
        self.stream_path = Path(
            stream_path
        )

    def _existing_record_ids(self):

        if not self.stream_path.exists():
            return set()

        record_ids = set()

        try:

            with self.stream_path.open(
                "r",
                encoding="utf-8",
            ) as handle:

                for raw in handle:

                    raw = raw.strip()

                    if not raw:
                        continue

                    try:
                        event = json.loads(
                            raw
                        )
                    except json.JSONDecodeError:
                        continue

                    if not isinstance(
                        event,
                        dict,
                    ):
                        continue

                    record_id = event.get(
                        "record_id"
                    )

                    if not isinstance(
                        record_id,
                        str,
                    ):
                        continue

                    if not record_id.strip():
                        continue

                    record_ids.add(
                        record_id
                    )

        except OSError:
            raise

        return record_ids

    def _append_event(
        self,
        event,
    ):

        self.stream_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        payload = json.dumps(
            event,
            ensure_ascii=False,
            separators=(
                ",",
                ":",
            ),
        )

        with self.stream_path.open(
            "a",
            encoding="utf-8",
        ) as handle:

            handle.write(
                payload
            )

            handle.write(
                "\n"
            )

            handle.flush()

            os.fsync(
                handle.fileno()
            )

    def run_once(self):

        cursor = (
            self.checkpoint.load()
        )

        if cursor is None:

            if not self.checkpoint.is_initialized():

                baseline = (
                    self.source.latest_cursor()
                )

                if baseline is None:

                    self.checkpoint.mark_initialized_empty()

                    return 0

                self.checkpoint.save(
                    baseline
                )

                return 0

        entries = self.source.read(
            after_cursor=cursor
        )

        emitted = 0

        existing_record_ids = (
            self._existing_record_ids()
        )

        for entry in entries:

            entry_cursor = entry.get(
                "__CURSOR"
            )

            if not isinstance(
                entry_cursor,
                str,
            ):
                continue

            if not entry_cursor.strip():
                continue

            event = parse_ssh_failure(
                entry
            )

            if event is not None:

                record_id = event.get(
                    "record_id"
                )

                if (
                    isinstance(
                        record_id,
                        str,
                    )
                    and record_id
                    not in existing_record_ids
                ):

                    self._append_event(
                        event
                    )

                    existing_record_ids.add(
                        record_id
                    )

                    emitted += 1

            self.checkpoint.save(
                entry_cursor
            )

        return emitted


def _timestamp_from_journal(entry):

    raw = entry.get(
        "__REALTIME_TIMESTAMP"
    )

    if raw is None:
        return None

    try:
        microseconds = int(raw)
    except (TypeError, ValueError):
        return None

    seconds = (
        microseconds / 1_000_000
    )

    return (
        datetime.fromtimestamp(
            seconds,
            tz=timezone.utc,
        )
        .isoformat()
        .replace(
            "+00:00",
            "Z",
        )
    )


def _record_id(entry):

    cursor = str(
        entry.get(
            "__CURSOR",
            "",
        )
    )

    message = str(
        entry.get(
            "MESSAGE",
            "",
        )
    )

    fingerprint = hashlib.sha256(
        (
            cursor
            + "\x00"
            + message
        ).encode(
            "utf-8"
        )
    ).hexdigest()[:16]

    return (
        f"LINUX-SSH-{fingerprint}"
    )


def parse_ssh_failure(entry):

    if not isinstance(
        entry,
        dict,
    ):
        return None

    cursor = entry.get(
        "__CURSOR"
    )

    if not isinstance(
        cursor,
        str,
    ):
        return None

    if not cursor.strip():
        return None

    message = entry.get(
        "MESSAGE"
    )

    if not isinstance(
        message,
        str,
    ):
        return None

    match = (
        _INVALID_USER_PATTERN.match(
            message
        )
        or
        _EXISTING_USER_PATTERN.match(
            message
        )
    )

    if match is None:
        return None

    ip = match.group(
        "ip"
    )

    try:
        ipaddress.ip_address(
            ip
        )
    except ValueError:
        return None

    timestamp = (
        _timestamp_from_journal(
            entry
        )
    )

    if timestamp is None:
        return None

    return {
        "record_id": (
            _record_id(
                entry
            )
        ),
        "event_id": (
            "SSH-AUTH-FAIL"
        ),
        "timestamp": timestamp,
        "ip": ip,
        "hostname": (
            entry.get(
                "_HOSTNAME"
            )
        ),
        "username": (
            match.group(
                "username"
            )
        ),
        "type": "login_failed",
        "action": "login_failed",
        "message": message,
        "journal_cursor": (
            entry.get(
                "__CURSOR"
            )
        ),
    }
