import json
import subprocess

import pytest

from engine.services.windows_firewall_backend import (
    WindowsFirewallBackend,
)


TARGET = "192.168.20.130"

RULE_NAME = (
    "SOC-LAB-BLOCK-192-168-20-130"
)


class FakeRunner:

    def __init__(
        self,
        status,
        returncode=0,
        stderr="",
    ):

        self.status = status
        self.returncode = returncode
        self.stderr = stderr
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

        stdout = ""

        if self.returncode == 0:
            stdout = (
                json.dumps(
                    {
                        "status":
                            self.status,
                        "rule_name":
                            RULE_NAME,
                        "target":
                            TARGET,
                    }
                )
                + "\n"
            )

        return subprocess.CompletedProcess(
            args=command,
            returncode=self.returncode,
            stdout=stdout,
            stderr=self.stderr,
        )


def test_block_creates_firewall_rule():

    runner = FakeRunner(
        "CREATED"
    )

    backend = WindowsFirewallBackend(
        runner=runner
    )

    result = backend.block(
        TARGET
    )

    assert result == {
        "status": "CREATED",
        "rule_name": RULE_NAME,
        "target": TARGET,
    }

    assert len(
        runner.calls
    ) == 1

    command, kwargs = (
        runner.calls[0]
    )

    assert command[0] == \
        "powershell.exe"

    assert "-NoProfile" in command

    assert "-NonInteractive" in command

    assert (
        TARGET
        not in
        " ".join(command)
    )

    assert "shell" not in kwargs

    assert kwargs[
        "check"
    ] is False

    assert "env" not in kwargs

    payload = json.loads(
        kwargs["input"]
    )

    assert payload == {
        "rule_name": RULE_NAME,
        "target": TARGET,
    }


def test_existing_block_is_idempotent():

    runner = FakeRunner(
        "EXISTS"
    )

    backend = WindowsFirewallBackend(
        runner=runner
    )

    result = backend.block(
        TARGET
    )

    assert result[
        "status"
    ] == "EXISTS"


def test_unblock_removes_firewall_rule():

    runner = FakeRunner(
        "REMOVED"
    )

    backend = WindowsFirewallBackend(
        runner=runner
    )

    result = backend.unblock(
        TARGET
    )

    assert result[
        "status"
    ] == "REMOVED"


def test_missing_unblock_is_idempotent():

    runner = FakeRunner(
        "MISSING"
    )

    backend = WindowsFirewallBackend(
        runner=runner
    )

    result = backend.unblock(
        TARGET
    )

    assert result[
        "status"
    ] == "MISSING"


@pytest.mark.parametrize(
    "status, expected",
    [
        ("EXISTS", True),
        ("MISSING", False),
    ],
)
def test_query_reports_block_state(
    status,
    expected,
):

    runner = FakeRunner(
        status
    )

    backend = WindowsFirewallBackend(
        runner=runner
    )

    assert (
        backend.is_blocked(
            TARGET
        )
        is expected
    )


@pytest.mark.parametrize(
    "target",
    [
        "",
        "not-an-ip",
        "127.0.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "169.254.10.20",
        "::1",
        "2001:db8::1",
    ],
)
def test_invalid_targets_are_rejected(
    target,
):

    runner = FakeRunner(
        "CREATED"
    )

    backend = WindowsFirewallBackend(
        runner=runner
    )

    with pytest.raises(
        ValueError
    ):
        backend.block(
            target
        )

    assert runner.calls == []


def test_canonical_ipv4_rule_name():

    assert (
        WindowsFirewallBackend.rule_name_for(
            TARGET
        )
        == RULE_NAME
    )


def test_powershell_failure_is_not_success():

    runner = FakeRunner(
        status="CREATED",
        returncode=1,
        stderr="Access is denied",
    )

    backend = WindowsFirewallBackend(
        runner=runner
    )

    with pytest.raises(
        RuntimeError,
        match="Access is denied",
    ):
        backend.block(
            TARGET
        )


def test_unexpected_backend_status_fails_closed():

    runner = FakeRunner(
        "UNKNOWN"
    )

    backend = WindowsFirewallBackend(
        runner=runner
    )

    with pytest.raises(
        RuntimeError,
        match="Unexpected firewall block status",
    ):
        backend.block(
            TARGET
        )
