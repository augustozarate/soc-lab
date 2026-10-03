from engine.infrastructure.linux_ssh_collector import (
    JournalCursorCheckpoint,
    JournalSource,
    LinuxSSHCollector,
    parse_ssh_failure,
)


def test_parse_invalid_user_failed_password():

    entry = {
        "__CURSOR": "s=lab;i=001",
        "__REALTIME_TIMESTAMP": "1790986676236637",
        "_HOSTNAME": "soc-ubuntu-01",
        "MESSAGE": (
            "Failed password for invalid user "
            "nonexistent-lab-user "
            "from 192.168.20.130 "
            "port 38462 ssh2"
        ),
    }

    event = parse_ssh_failure(entry)

    assert event is not None

    assert event["ip"] == "192.168.20.130"

    assert (
        event["username"]
        == "nonexistent-lab-user"
    )

    assert event["type"] == "login_failed"
    assert event["action"] == "login_failed"

    assert event["hostname"] == "soc-ubuntu-01"

    assert event["journal_cursor"] == "s=lab;i=001"

    assert event["message"] == entry["MESSAGE"]

    assert event["timestamp"].endswith("Z")

    assert event["record_id"].startswith(
        "LINUX-SSH-"
    )

    assert event["event_id"] == (
        "SSH-AUTH-FAIL"
    )


def test_parse_existing_user_failed_password():

    entry = {
        "__CURSOR": "s=lab;i=002",
        "__REALTIME_TIMESTAMP": "1790986677549581",
        "_HOSTNAME": "soc-ubuntu-01",
        "MESSAGE": (
            "Failed password for augus "
            "from 192.168.20.130 "
            "port 41234 ssh2"
        ),
    }

    event = parse_ssh_failure(entry)

    assert event is not None
    assert event["username"] == "augus"
    assert event["ip"] == "192.168.20.130"

    assert event["type"] == "login_failed"
    assert event["action"] == "login_failed"


def test_non_failed_password_entry_is_ignored():

    entry = {
        "__CURSOR": "s=lab;i=003",
        "__REALTIME_TIMESTAMP": "1790986679000000",
        "_HOSTNAME": "soc-ubuntu-01",
        "MESSAGE": (
            "Accepted password for augus "
            "from 192.168.20.130 "
            "port 51234 ssh2"
        ),
    }

    assert parse_ssh_failure(entry) is None


def test_missing_journal_cursor_is_rejected():

    entry = {
        "__REALTIME_TIMESTAMP": "1790986676236637",
        "_HOSTNAME": "soc-ubuntu-01",
        "MESSAGE": (
            "Failed password for invalid user "
            "alice "
            "from 192.168.20.130 "
            "port 38462 ssh2"
        ),
    }

    assert parse_ssh_failure(entry) is None


def test_empty_journal_cursor_is_rejected():

    entry = {
        "__CURSOR": "",
        "__REALTIME_TIMESTAMP": "1790986676236637",
        "_HOSTNAME": "soc-ubuntu-01",
        "MESSAGE": (
            "Failed password for alice "
            "from 192.168.20.130 "
            "port 38462 ssh2"
        ),
    }

    assert parse_ssh_failure(entry) is None


def test_invalid_realtime_timestamp_is_rejected():

    entry = {
        "__CURSOR": "s=lab;i=004",
        "__REALTIME_TIMESTAMP": "not-a-timestamp",
        "_HOSTNAME": "soc-ubuntu-01",
        "MESSAGE": (
            "Failed password for alice "
            "from 192.168.20.130 "
            "port 38462 ssh2"
        ),
    }

    assert parse_ssh_failure(entry) is None


def test_invalid_ip_address_is_rejected():

    entry = {
        "__CURSOR": "s=lab;i=005",
        "__REALTIME_TIMESTAMP": "1790986676236637",
        "_HOSTNAME": "soc-ubuntu-01",
        "MESSAGE": (
            "Failed password for alice "
            "from definitely-not-an-ip "
            "port 38462 ssh2"
        ),
    }

    assert parse_ssh_failure(entry) is None


def test_ipv6_failed_password_is_supported():

    entry = {
        "__CURSOR": "s=lab;i=006",
        "__REALTIME_TIMESTAMP": "1790986676236637",
        "_HOSTNAME": "soc-ubuntu-01",
        "MESSAGE": (
            "Failed password for alice "
            "from 2001:db8::130 "
            "port 38462 ssh2"
        ),
    }

    event = parse_ssh_failure(entry)

    assert event is not None

    assert event["ip"] == "2001:db8::130"
    assert event["username"] == "alice"


def test_record_id_is_deterministic():

    entry = {
        "__CURSOR": "s=lab;i=007",
        "__REALTIME_TIMESTAMP": "1790986676236637",
        "_HOSTNAME": "soc-ubuntu-01",
        "MESSAGE": (
            "Failed password for alice "
            "from 192.168.20.130 "
            "port 38462 ssh2"
        ),
    }

    first = parse_ssh_failure(entry)
    second = parse_ssh_failure(entry)

    assert first is not None
    assert second is not None

    assert (
        first["record_id"]
        == second["record_id"]
    )



def test_checkpoint_missing_file_returns_none(
    tmp_path,
):

    checkpoint = JournalCursorCheckpoint(
        tmp_path
        / "linux_ssh_checkpoint.json"
    )

    assert checkpoint.load() is None


def test_checkpoint_round_trip(
    tmp_path,
):

    path = (
        tmp_path
        / "linux_ssh_checkpoint.json"
    )

    checkpoint = JournalCursorCheckpoint(
        path
    )

    checkpoint.save(
        "s=lab;i=100"
    )

    assert checkpoint.load() == (
        "s=lab;i=100"
    )


def test_checkpoint_overwrites_previous_cursor(
    tmp_path,
):

    path = (
        tmp_path
        / "linux_ssh_checkpoint.json"
    )

    checkpoint = JournalCursorCheckpoint(
        path
    )

    checkpoint.save(
        "s=lab;i=100"
    )

    checkpoint.save(
        "s=lab;i=101"
    )

    assert checkpoint.load() == (
        "s=lab;i=101"
    )


def test_checkpoint_rejects_empty_cursor(
    tmp_path,
):

    checkpoint = JournalCursorCheckpoint(
        tmp_path
        / "linux_ssh_checkpoint.json"
    )

    try:
        checkpoint.save("")
    except ValueError:
        pass
    else:
        raise AssertionError(
            "empty cursor must be rejected"
        )


def test_checkpoint_corrupt_json_returns_none(
    tmp_path,
):

    path = (
        tmp_path
        / "linux_ssh_checkpoint.json"
    )

    path.write_text(
        "{ definitely broken json"
    )

    checkpoint = JournalCursorCheckpoint(
        path
    )

    assert checkpoint.load() is None


def test_checkpoint_uses_expected_json_shape(
    tmp_path,
):

    import json

    path = (
        tmp_path
        / "linux_ssh_checkpoint.json"
    )

    checkpoint = JournalCursorCheckpoint(
        path
    )

    checkpoint.save(
        "s=lab;i=200"
    )

    data = json.loads(
        path.read_text()
    )

    assert data == {
        "cursor": "s=lab;i=200"
    }



class _FakeCompletedProcess:

    def __init__(
        self,
        stdout="",
        returncode=0,
    ):
        self.stdout = stdout
        self.returncode = returncode


class _RecordingRunner:

    def __init__(
        self,
        result,
    ):
        self.result = result
        self.calls = []

    def __call__(
        self,
        command,
        **kwargs,
    ):
        self.calls.append(
            (
                command,
                kwargs,
            )
        )

        return self.result


def test_journal_source_without_cursor_omits_after_cursor():

    runner = _RecordingRunner(
        _FakeCompletedProcess(
            stdout=""
        )
    )

    source = JournalSource(
        runner=runner
    )

    entries = source.read()

    assert entries == []

    command, kwargs = runner.calls[0]

    assert "--after-cursor" not in command

    assert "-u" in command
    assert "ssh" in command

    assert "-o" in command
    assert "json" in command


def test_journal_source_with_cursor_uses_after_cursor():

    runner = _RecordingRunner(
        _FakeCompletedProcess(
            stdout=""
        )
    )

    source = JournalSource(
        runner=runner
    )

    source.read(
        after_cursor="s=lab;i=100"
    )

    command, kwargs = runner.calls[0]

    assert "--after-cursor" in command

    index = command.index(
        "--after-cursor"
    )

    assert command[index + 1] == (
        "s=lab;i=100"
    )


def test_journal_source_parses_json_lines():

    runner = _RecordingRunner(
        _FakeCompletedProcess(
            stdout=(
                '{"MESSAGE":"one","__CURSOR":"a"}\n'
                '{"MESSAGE":"two","__CURSOR":"b"}\n'
            )
        )
    )

    source = JournalSource(
        runner=runner
    )

    entries = source.read()

    assert entries == [
        {
            "MESSAGE": "one",
            "__CURSOR": "a",
        },
        {
            "MESSAGE": "two",
            "__CURSOR": "b",
        },
    ]


def test_journal_source_skips_bad_json_lines():

    runner = _RecordingRunner(
        _FakeCompletedProcess(
            stdout=(
                '{"MESSAGE":"good","__CURSOR":"a"}\n'
                'definitely-not-json\n'
                '{"MESSAGE":"also-good","__CURSOR":"b"}\n'
            )
        )
    )

    source = JournalSource(
        runner=runner
    )

    entries = source.read()

    assert len(entries) == 2

    assert entries[0]["__CURSOR"] == "a"
    assert entries[1]["__CURSOR"] == "b"


def test_journal_source_rejects_empty_after_cursor():

    runner = _RecordingRunner(
        _FakeCompletedProcess()
    )

    source = JournalSource(
        runner=runner
    )

    try:
        source.read(
            after_cursor=""
        )
    except ValueError:
        pass
    else:
        raise AssertionError(
            "empty after_cursor must be rejected"
        )


def test_journal_source_uses_noninteractive_command():

    runner = _RecordingRunner(
        _FakeCompletedProcess(
            stdout=""
        )
    )

    source = JournalSource(
        runner=runner
    )

    source.read()

    command, kwargs = runner.calls[0]

    assert "--no-pager" in command

    assert kwargs["capture_output"] is True
    assert kwargs["text"] is True
    assert kwargs["check"] is False


def test_journal_source_nonzero_returncode_raises():

    runner = _RecordingRunner(
        _FakeCompletedProcess(
            stdout=(
                '{"MESSAGE":"partial"}\n'
            ),
            returncode=1,
        )
    )

    source = JournalSource(
        runner=runner
    )

    try:
        source.read()
    except RuntimeError:
        pass
    else:
        raise AssertionError(
            "journalctl failure must raise"
        )


def test_journal_source_latest_cursor():

    runner = _RecordingRunner(
        _FakeCompletedProcess(
            stdout=(
                '{"__CURSOR":"s=lab;i=500",'
                '"MESSAGE":"latest"}\n'
            )
        )
    )

    source = JournalSource(
        runner=runner
    )

    cursor = source.latest_cursor()

    assert cursor == "s=lab;i=500"

    command, kwargs = runner.calls[0]

    assert "-n" in command

    index = command.index(
        "-n"
    )

    assert command[index + 1] == "1"

    assert "-u" in command
    assert "ssh" in command
    assert "-o" in command
    assert "json" in command
    assert "--no-pager" in command


def test_journal_source_latest_cursor_empty_journal():

    runner = _RecordingRunner(
        _FakeCompletedProcess(
            stdout=""
        )
    )

    source = JournalSource(
        runner=runner
    )

    assert source.latest_cursor() is None


def test_journal_source_latest_cursor_missing_cursor():

    runner = _RecordingRunner(
        _FakeCompletedProcess(
            stdout='{"MESSAGE":"no cursor"}\n'
        )
    )

    source = JournalSource(
        runner=runner
    )

    assert source.latest_cursor() is None


def test_journal_source_latest_cursor_nonzero_returncode_raises():

    runner = _RecordingRunner(
        _FakeCompletedProcess(
            stdout="",
            returncode=1,
        )
    )

    source = JournalSource(
        runner=runner
    )

    try:
        source.latest_cursor()
    except RuntimeError:
        pass
    else:
        raise AssertionError(
            "journalctl failure must raise"
        )



class _FakeJournalSource:

    def __init__(
        self,
        latest_cursor=None,
        entries=None,
    ):
        self._latest_cursor = latest_cursor
        self._entries = (
            list(entries)
            if entries is not None
            else []
        )
        self.latest_cursor_calls = 0
        self.read_calls = []

    def latest_cursor(self):
        self.latest_cursor_calls += 1
        return self._latest_cursor

    def read(
        self,
        after_cursor=None,
    ):
        self.read_calls.append(
            after_cursor
        )
        return list(
            self._entries
        )


def _ssh_failure_entry(
    cursor,
    username="alice",
    ip="192.168.20.130",
):

    return {
        "__CURSOR": cursor,
        "__REALTIME_TIMESTAMP": (
            "1790986676236637"
        ),
        "_HOSTNAME": "soc-ubuntu-01",
        "MESSAGE": (
            f"Failed password for {username} "
            f"from {ip} "
            "port 38462 ssh2"
        ),
    }


def test_collector_first_run_sets_baseline_without_emitting(
    tmp_path,
):

    stream = (
        tmp_path
        / "stream.jsonl"
    )

    checkpoint = JournalCursorCheckpoint(
        tmp_path
        / "collector_checkpoint.json"
    )

    source = _FakeJournalSource(
        latest_cursor="s=lab;i=500"
    )

    collector = LinuxSSHCollector(
        source=source,
        checkpoint=checkpoint,
        stream_path=stream,
    )

    emitted = collector.run_once()

    assert emitted == 0

    assert checkpoint.load() == (
        "s=lab;i=500"
    )

    assert source.latest_cursor_calls == 1
    assert source.read_calls == []

    assert not stream.exists()


def test_collector_reads_after_saved_cursor(
    tmp_path,
):

    stream = (
        tmp_path
        / "stream.jsonl"
    )

    checkpoint = JournalCursorCheckpoint(
        tmp_path
        / "collector_checkpoint.json"
    )

    checkpoint.save(
        "s=lab;i=500"
    )

    source = _FakeJournalSource(
        entries=[
            _ssh_failure_entry(
                "s=lab;i=501"
            ),
        ]
    )

    collector = LinuxSSHCollector(
        source=source,
        checkpoint=checkpoint,
        stream_path=stream,
    )

    emitted = collector.run_once()

    assert emitted == 1

    assert source.read_calls == [
        "s=lab;i=500"
    ]

    assert checkpoint.load() == (
        "s=lab;i=501"
    )

    assert stream.exists()


def test_collector_appends_normalized_event(
    tmp_path,
):

    import json

    stream = (
        tmp_path
        / "stream.jsonl"
    )

    checkpoint = JournalCursorCheckpoint(
        tmp_path
        / "collector_checkpoint.json"
    )

    checkpoint.save(
        "s=lab;i=600"
    )

    source = _FakeJournalSource(
        entries=[
            _ssh_failure_entry(
                "s=lab;i=601",
                username="augus",
            ),
        ]
    )

    collector = LinuxSSHCollector(
        source=source,
        checkpoint=checkpoint,
        stream_path=stream,
    )

    assert collector.run_once() == 1

    lines = stream.read_text().splitlines()

    assert len(lines) == 1

    event = json.loads(
        lines[0]
    )

    assert event["username"] == "augus"
    assert event["ip"] == "192.168.20.130"
    assert event["type"] == "login_failed"
    assert event["action"] == "login_failed"
    assert event["journal_cursor"] == (
        "s=lab;i=601"
    )


def test_collector_advances_cursor_for_ignored_entry(
    tmp_path,
):

    stream = (
        tmp_path
        / "stream.jsonl"
    )

    checkpoint = JournalCursorCheckpoint(
        tmp_path
        / "collector_checkpoint.json"
    )

    checkpoint.save(
        "s=lab;i=700"
    )

    source = _FakeJournalSource(
        entries=[
            {
                "__CURSOR": "s=lab;i=701",
                "__REALTIME_TIMESTAMP": (
                    "1790986676236637"
                ),
                "_HOSTNAME": (
                    "soc-ubuntu-01"
                ),
                "MESSAGE": (
                    "Accepted password for alice "
                    "from 192.168.20.130 "
                    "port 38462 ssh2"
                ),
            },
        ]
    )

    collector = LinuxSSHCollector(
        source=source,
        checkpoint=checkpoint,
        stream_path=stream,
    )

    emitted = collector.run_once()

    assert emitted == 0

    assert checkpoint.load() == (
        "s=lab;i=701"
    )

    assert not stream.exists()


def test_collector_processes_multiple_entries_in_order(
    tmp_path,
):

    import json

    stream = (
        tmp_path
        / "stream.jsonl"
    )

    checkpoint = JournalCursorCheckpoint(
        tmp_path
        / "collector_checkpoint.json"
    )

    checkpoint.save(
        "s=lab;i=800"
    )

    source = _FakeJournalSource(
        entries=[
            _ssh_failure_entry(
                "s=lab;i=801"
            ),
            {
                "__CURSOR": "s=lab;i=802",
                "__REALTIME_TIMESTAMP": (
                    "1790986676236637"
                ),
                "_HOSTNAME": (
                    "soc-ubuntu-01"
                ),
                "MESSAGE": (
                    "Accepted password for alice "
                    "from 192.168.20.130 "
                    "port 38462 ssh2"
                ),
            },
            _ssh_failure_entry(
                "s=lab;i=803",
                username="bob",
            ),
        ]
    )

    collector = LinuxSSHCollector(
        source=source,
        checkpoint=checkpoint,
        stream_path=stream,
    )

    emitted = collector.run_once()

    assert emitted == 2

    assert checkpoint.load() == (
        "s=lab;i=803"
    )

    lines = stream.read_text().splitlines()

    assert len(lines) == 2

    events = [
        json.loads(line)
        for line in lines
    ]

    assert events[0]["journal_cursor"] == (
        "s=lab;i=801"
    )

    assert events[1]["journal_cursor"] == (
        "s=lab;i=803"
    )


def test_collector_second_run_uses_updated_checkpoint(
    tmp_path,
):

    stream = (
        tmp_path
        / "stream.jsonl"
    )

    checkpoint = JournalCursorCheckpoint(
        tmp_path
        / "collector_checkpoint.json"
    )

    checkpoint.save(
        "s=lab;i=900"
    )

    source = _FakeJournalSource(
        entries=[
            _ssh_failure_entry(
                "s=lab;i=901"
            ),
        ]
    )

    collector = LinuxSSHCollector(
        source=source,
        checkpoint=checkpoint,
        stream_path=stream,
    )

    assert collector.run_once() == 1

    source._entries = []

    assert collector.run_once() == 0

    assert source.read_calls == [
        "s=lab;i=900",
        "s=lab;i=901",
    ]

    assert checkpoint.load() == (
        "s=lab;i=901"
    )


def test_checkpoint_can_mark_empty_baseline(
    tmp_path,
):

    checkpoint = JournalCursorCheckpoint(
        tmp_path
        / "collector_checkpoint.json"
    )

    assert checkpoint.is_initialized() is False

    checkpoint.mark_initialized_empty()

    assert checkpoint.is_initialized() is True
    assert checkpoint.load() is None


def test_checkpoint_saved_cursor_is_initialized(
    tmp_path,
):

    checkpoint = JournalCursorCheckpoint(
        tmp_path
        / "collector_checkpoint.json"
    )

    checkpoint.save(
        "s=lab;i=1000"
    )

    assert checkpoint.is_initialized() is True

    assert checkpoint.load() == (
        "s=lab;i=1000"
    )


def test_collector_empty_first_run_does_not_lose_first_future_event(
    tmp_path,
):

    stream = (
        tmp_path
        / "stream.jsonl"
    )

    checkpoint = JournalCursorCheckpoint(
        tmp_path
        / "collector_checkpoint.json"
    )

    source = _FakeJournalSource(
        latest_cursor=None,
        entries=[],
    )

    collector = LinuxSSHCollector(
        source=source,
        checkpoint=checkpoint,
        stream_path=stream,
    )

    first_emitted = collector.run_once()

    assert first_emitted == 0

    assert checkpoint.is_initialized() is True
    assert checkpoint.load() is None

    assert source.latest_cursor_calls == 1
    assert source.read_calls == []

    source._latest_cursor = (
        "s=lab;i=1001"
    )

    source._entries = [
        _ssh_failure_entry(
            "s=lab;i=1001"
        ),
    ]

    second_emitted = collector.run_once()

    assert second_emitted == 1

    assert source.latest_cursor_calls == 1

    assert source.read_calls == [
        None
    ]

    assert checkpoint.load() == (
        "s=lab;i=1001"
    )

    assert stream.exists()

    assert len(
        stream.read_text().splitlines()
    ) == 1


def test_collector_restart_uses_persisted_cursor_without_replay(
    tmp_path,
):

    stream = (
        tmp_path
        / "stream.jsonl"
    )

    checkpoint_path = (
        tmp_path
        / "collector_checkpoint.json"
    )

    checkpoint_one = JournalCursorCheckpoint(
        checkpoint_path
    )

    checkpoint_one.save(
        "s=lab;i=1100"
    )

    source_one = _FakeJournalSource(
        entries=[
            _ssh_failure_entry(
                "s=lab;i=1101"
            ),
        ]
    )

    collector_one = LinuxSSHCollector(
        source=source_one,
        checkpoint=checkpoint_one,
        stream_path=stream,
    )

    assert collector_one.run_once() == 1

    assert checkpoint_one.load() == (
        "s=lab;i=1101"
    )

    assert len(
        stream.read_text().splitlines()
    ) == 1

    checkpoint_two = JournalCursorCheckpoint(
        checkpoint_path
    )

    source_two = _FakeJournalSource(
        entries=[]
    )

    collector_two = LinuxSSHCollector(
        source=source_two,
        checkpoint=checkpoint_two,
        stream_path=stream,
    )

    assert collector_two.run_once() == 0

    assert source_two.latest_cursor_calls == 0

    assert source_two.read_calls == [
        "s=lab;i=1101"
    ]

    assert checkpoint_two.load() == (
        "s=lab;i=1101"
    )

    assert len(
        stream.read_text().splitlines()
    ) == 1


class _FailingCheckpoint:

    def __init__(
        self,
        delegate,
    ):
        self.delegate = delegate
        self.fail_next_save = True

    def load(self):
        return self.delegate.load()

    def is_initialized(self):
        return self.delegate.is_initialized()

    def mark_initialized_empty(self):
        return self.delegate.mark_initialized_empty()

    def save(
        self,
        cursor,
    ):

        if self.fail_next_save:
            self.fail_next_save = False
            raise RuntimeError(
                "simulated checkpoint crash"
            )

        return self.delegate.save(
            cursor
        )


def test_collector_restart_after_append_before_checkpoint_does_not_duplicate(
    tmp_path,
):

    import json

    stream = (
        tmp_path
        / "stream.jsonl"
    )

    checkpoint_path = (
        tmp_path
        / "collector_checkpoint.json"
    )

    durable_checkpoint = JournalCursorCheckpoint(
        checkpoint_path
    )

    durable_checkpoint.save(
        "s=lab;i=1200"
    )

    failing_checkpoint = _FailingCheckpoint(
        durable_checkpoint
    )

    entry = _ssh_failure_entry(
        "s=lab;i=1201"
    )

    source_one = _FakeJournalSource(
        entries=[
            entry
        ]
    )

    collector_one = LinuxSSHCollector(
        source=source_one,
        checkpoint=failing_checkpoint,
        stream_path=stream,
    )

    try:
        collector_one.run_once()
    except RuntimeError as exc:
        assert (
            "simulated checkpoint crash"
            in str(exc)
        )
    else:
        raise AssertionError(
            "checkpoint failure must propagate"
        )

    lines_after_crash = (
        stream.read_text().splitlines()
    )

    assert len(
        lines_after_crash
    ) == 1

    event_after_crash = json.loads(
        lines_after_crash[0]
    )

    assert event_after_crash[
        "journal_cursor"
    ] == "s=lab;i=1201"

    assert durable_checkpoint.load() == (
        "s=lab;i=1200"
    )

    restarted_checkpoint = JournalCursorCheckpoint(
        checkpoint_path
    )

    source_two = _FakeJournalSource(
        entries=[
            entry
        ]
    )

    collector_two = LinuxSSHCollector(
        source=source_two,
        checkpoint=restarted_checkpoint,
        stream_path=stream,
    )

    emitted = collector_two.run_once()

    assert emitted == 0

    assert restarted_checkpoint.load() == (
        "s=lab;i=1201"
    )

    lines_after_restart = (
        stream.read_text().splitlines()
    )

    assert len(
        lines_after_restart
    ) == 1


def test_collector_does_not_duplicate_existing_record_id(
    tmp_path,
):

    import json

    stream = (
        tmp_path
        / "stream.jsonl"
    )

    checkpoint = JournalCursorCheckpoint(
        tmp_path
        / "collector_checkpoint.json"
    )

    checkpoint.save(
        "s=lab;i=1300"
    )

    entry = _ssh_failure_entry(
        "s=lab;i=1301"
    )

    event = parse_ssh_failure(
        entry
    )

    assert event is not None

    stream.write_text(
        json.dumps(
            event
        )
        + "\n"
    )

    source = _FakeJournalSource(
        entries=[
            entry
        ]
    )

    collector = LinuxSSHCollector(
        source=source,
        checkpoint=checkpoint,
        stream_path=stream,
    )

    emitted = collector.run_once()

    assert emitted == 0

    assert checkpoint.load() == (
        "s=lab;i=1301"
    )

    assert len(
        stream.read_text().splitlines()
    ) == 1


def test_collector_idempotency_scan_tolerates_bad_json(
    tmp_path,
):

    import json

    stream = (
        tmp_path
        / "stream.jsonl"
    )

    checkpoint = JournalCursorCheckpoint(
        tmp_path
        / "collector_checkpoint.json"
    )

    checkpoint.save(
        "s=lab;i=1400"
    )

    entry = _ssh_failure_entry(
        "s=lab;i=1401"
    )

    event = parse_ssh_failure(
        entry
    )

    assert event is not None

    stream.write_text(
        "definitely-not-json\n"
        + json.dumps(
            event
        )
        + "\n"
    )

    source = _FakeJournalSource(
        entries=[
            entry
        ]
    )

    collector = LinuxSSHCollector(
        source=source,
        checkpoint=checkpoint,
        stream_path=stream,
    )

    emitted = collector.run_once()

    assert emitted == 0

    assert checkpoint.load() == (
        "s=lab;i=1401"
    )

    lines = stream.read_text().splitlines()

    assert len(lines) == 2
