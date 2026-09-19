import ipaddress
import json
import os
import subprocess


class WindowsFirewallBackend:

    RULE_PREFIX = "SOC-LAB-BLOCK"

    _BLOCK_SCRIPT = r'''
$ErrorActionPreference = "Stop"

$ruleName = $env:SOC_LAB_RULE_NAME
$targetIp = $env:SOC_LAB_TARGET_IP

try {

    $rules = @(
        Get-NetFirewallRule `
            -DisplayName $ruleName `
            -ErrorAction SilentlyContinue
    )

    if ($rules.Count -gt 1) {
        throw (
            "Multiple firewall rules found for " +
            $ruleName
        )
    }

    if ($rules.Count -eq 1) {

        $rule = $rules[0]

        $filters = @(
            $rule |
            Get-NetFirewallAddressFilter
        )

        $addresses = @()

        foreach ($filter in $filters) {
            $addresses += @(
                $filter.RemoteAddress
            )
        }

        if (
            $addresses -notcontains $targetIp
        ) {
            throw (
                "Existing firewall rule has " +
                "unexpected RemoteAddress"
            )
        }

        if (
            $rule.Direction.ToString() -ne
            "Inbound"
        ) {
            throw (
                "Existing firewall rule has " +
                "unexpected direction"
            )
        }

        if (
            $rule.Action.ToString() -ne
            "Block"
        ) {
            throw (
                "Existing firewall rule has " +
                "unexpected action"
            )
        }

        if (
            $rule.Enabled.ToString() -ne
            "True"
        ) {
            throw (
                "Existing firewall rule is disabled"
            )
        }

        [PSCustomObject]@{
            status = "EXISTS"
            rule_name = $ruleName
            target = $targetIp
        } |
        ConvertTo-Json -Compress

        exit 0
    }

    New-NetFirewallRule `
        -DisplayName $ruleName `
        -Group "SOC-LAB" `
        -Description (
            "SOC Lab automated inbound block for " +
            $targetIp
        ) `
        -Direction Inbound `
        -Action Block `
        -RemoteAddress $targetIp `
        -Profile Any `
        -Enabled True |
        Out-Null

    [PSCustomObject]@{
        status = "CREATED"
        rule_name = $ruleName
        target = $targetIp
    } |
    ConvertTo-Json -Compress

    exit 0
}
catch {

    [Console]::Error.WriteLine(
        $_.Exception.Message
    )

    exit 1
}
'''

    _UNBLOCK_SCRIPT = r'''
$ErrorActionPreference = "Stop"

$ruleName = $env:SOC_LAB_RULE_NAME
$targetIp = $env:SOC_LAB_TARGET_IP

try {

    $rules = @(
        Get-NetFirewallRule `
            -DisplayName $ruleName `
            -ErrorAction SilentlyContinue
    )

    if ($rules.Count -eq 0) {

        [PSCustomObject]@{
            status = "MISSING"
            rule_name = $ruleName
            target = $targetIp
        } |
        ConvertTo-Json -Compress

        exit 0
    }

    if ($rules.Count -gt 1) {
        throw (
            "Multiple firewall rules found for " +
            $ruleName
        )
    }

    Remove-NetFirewallRule `
        -DisplayName $ruleName `
        -ErrorAction Stop

    [PSCustomObject]@{
        status = "REMOVED"
        rule_name = $ruleName
        target = $targetIp
    } |
    ConvertTo-Json -Compress

    exit 0
}
catch {

    [Console]::Error.WriteLine(
        $_.Exception.Message
    )

    exit 1
}
'''

    _QUERY_SCRIPT = r'''
$ErrorActionPreference = "Stop"

$ruleName = $env:SOC_LAB_RULE_NAME
$targetIp = $env:SOC_LAB_TARGET_IP

try {

    $rules = @(
        Get-NetFirewallRule `
            -DisplayName $ruleName `
            -ErrorAction SilentlyContinue
    )

    if ($rules.Count -eq 0) {

        [PSCustomObject]@{
            status = "MISSING"
            rule_name = $ruleName
            target = $targetIp
        } |
        ConvertTo-Json -Compress

        exit 0
    }

    if ($rules.Count -gt 1) {
        throw (
            "Multiple firewall rules found for " +
            $ruleName
        )
    }

    $rule = $rules[0]

    $filters = @(
        $rule |
        Get-NetFirewallAddressFilter
    )

    $addresses = @()

    foreach ($filter in $filters) {
        $addresses += @(
            $filter.RemoteAddress
        )
    }

    if (
        $addresses -notcontains $targetIp
    ) {
        throw (
            "Firewall rule RemoteAddress " +
            "does not match target"
        )
    }

    if (
        $rule.Direction.ToString() -ne
        "Inbound"
        -or
        $rule.Action.ToString() -ne
        "Block"
        -or
        $rule.Enabled.ToString() -ne
        "True"
    ) {
        throw (
            "Firewall rule exists but does " +
            "not represent an active inbound block"
        )
    }

    [PSCustomObject]@{
        status = "EXISTS"
        rule_name = $ruleName
        target = $targetIp
    } |
    ConvertTo-Json -Compress

    exit 0
}
catch {

    [Console]::Error.WriteLine(
        $_.Exception.Message
    )

    exit 1
}
'''

    def __init__(
        self,
        powershell_path="powershell.exe",
        runner=None,
        timeout_seconds=5.0,
    ):

        self.powershell_path = (
            powershell_path
        )

        self.runner = (
            runner
            or subprocess.run
        )

        self.timeout_seconds = (
            timeout_seconds
        )

    @staticmethod
    def validate_target(target):

        if not isinstance(
            target,
            str,
        ):
            raise ValueError(
                "Firewall target must be a string"
            )

        value = target.strip()

        if not value:
            raise ValueError(
                "Firewall target is empty"
            )

        try:
            address = (
                ipaddress.ip_address(
                    value
                )
            )

        except ValueError as exc:
            raise ValueError(
                "Invalid firewall target IP"
            ) from exc

        if address.version != 4:
            raise ValueError(
                "Only IPv4 firewall targets "
                "are supported"
            )

        if address.is_loopback:
            raise ValueError(
                "Loopback addresses cannot "
                "be blocked"
            )

        if address.is_multicast:
            raise ValueError(
                "Multicast addresses cannot "
                "be blocked"
            )

        if address.is_unspecified:
            raise ValueError(
                "Unspecified addresses cannot "
                "be blocked"
            )

        if address.is_link_local:
            raise ValueError(
                "Link-local addresses cannot "
                "be blocked"
            )

        return str(address)

    @classmethod
    def rule_name_for(cls, target):

        address = cls.validate_target(
            target
        )

        normalized = address.replace(
            ".",
            "-",
        )

        return (
            f"{cls.RULE_PREFIX}-"
            f"{normalized}"
        )

    def block(self, target):

        address = self.validate_target(
            target
        )

        result = self._execute(
            self._BLOCK_SCRIPT,
            address,
        )

        if result.get("status") not in {
            "CREATED",
            "EXISTS",
        }:
            raise RuntimeError(
                "Unexpected firewall block status: "
                f"{result.get('status')}"
            )

        return result

    def unblock(self, target):

        address = self.validate_target(
            target
        )

        result = self._execute(
            self._UNBLOCK_SCRIPT,
            address,
        )

        if result.get("status") not in {
            "REMOVED",
            "MISSING",
        }:
            raise RuntimeError(
                "Unexpected firewall unblock status: "
                f"{result.get('status')}"
            )

        return result

    def is_blocked(self, target):

        address = self.validate_target(
            target
        )

        result = self._execute(
            self._QUERY_SCRIPT,
            address,
        )

        status = result.get(
            "status"
        )

        if status == "EXISTS":
            return True

        if status == "MISSING":
            return False

        raise RuntimeError(
            "Unexpected firewall query status: "
            f"{status}"
        )

    def _execute(
        self,
        script,
        target,
    ):

        rule_name = self.rule_name_for(
            target
        )

        environment = os.environ.copy()

        environment[
            "SOC_LAB_RULE_NAME"
        ] = rule_name

        environment[
            "SOC_LAB_TARGET_IP"
        ] = target

        command = [
            self.powershell_path,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ]

        try:

            completed = self.runner(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
                env=environment,
            )

        except subprocess.TimeoutExpired as exc:

            raise RuntimeError(
                "Windows Firewall command "
                "timed out"
            ) from exc

        if completed.returncode != 0:

            detail = (
                completed.stderr.strip()
                or completed.stdout.strip()
                or "unknown PowerShell error"
            )

            raise RuntimeError(
                "Windows Firewall command failed: "
                f"{detail}"
            )

        output_lines = [
            line.strip()
            for line
            in completed.stdout.splitlines()
            if line.strip()
        ]

        if not output_lines:
            raise RuntimeError(
                "Windows Firewall command "
                "returned no result"
            )

        try:

            payload = json.loads(
                output_lines[-1]
            )

        except json.JSONDecodeError as exc:

            raise RuntimeError(
                "Windows Firewall returned "
                "invalid JSON"
            ) from exc

        if payload.get(
            "target"
        ) != target:

            raise RuntimeError(
                "Windows Firewall result target "
                "does not match request"
            )

        if payload.get(
            "rule_name"
        ) != rule_name:

            raise RuntimeError(
                "Windows Firewall result rule "
                "does not match request"
            )

        return payload
