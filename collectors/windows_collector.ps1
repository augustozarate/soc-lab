$projectRoot = (
    Resolve-Path (
        Join-Path $PSScriptRoot ".."
    )
).Path

$logsDir = Join-Path $projectRoot "logs"

New-Item `
    -ItemType Directory `
    -Force `
    -Path $logsDir |
    Out-Null

$path = Join-Path `
    $logsDir `
    "stream.jsonl"


# ==========================================
# INITIAL EVENT CHECKPOINT
# ==========================================

$latestEvent = (
    Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4625
    } -MaxEvents 1 -ErrorAction SilentlyContinue
)

if ($latestEvent) {
    $lastRecordId = $latestEvent.RecordId
}
else {
    $lastRecordId = 0
}

Write-Host (
    "[COLLECTOR] Starting after RecordId: {0}" `
    -f $lastRecordId
)


# ==========================================
# EVENT LOOP
# ==========================================

while ($true) {

    $events = Get-WinEvent `
        -LogName Security `
        -FilterXPath (
            "*[System[" +
            "(EventID=4625) and " +
            "(EventRecordID > $lastRecordId)" +
            "]]"
        ) `
        -ErrorAction SilentlyContinue |
        Sort-Object RecordId

    foreach ($e in $events) {

        $xml = [xml]$e.ToXml()

        $data = @{}

        foreach ($item in $xml.Event.EventData.Data) {
            $data[$item.Name] = $item.'#text'
        }

        $ip = $data.IpAddress

        if (
            !$ip `
            -or $ip -eq "-" `
            -or $ip -eq "::1"
        ) {

            $lastRecordId = [Math]::Max(
                $lastRecordId,
                $e.RecordId
            )

            continue
        }

        $obj = @{
            time = $e.TimeCreated.ToString(
                "HH:mm:ss"
            )

            record_id = $e.RecordId
            event_id = 4625
            level = "HIGH"
            ip = $ip
            username = $data.TargetUserName
            logon_type = $data.LogonType
            status = $data.Status
            substatus = $data.SubStatus
            message = "FAILED LOGIN"
        }

        $line = (
            $obj |
            ConvertTo-Json -Compress
        )

        $fs = [System.IO.File]::Open(
            $path,
            [System.IO.FileMode]::Append,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::ReadWrite
        )

        try {

            $sw = New-Object `
                System.IO.StreamWriter($fs)

            try {
                $sw.WriteLine($line)
                $sw.Flush()
            }
            finally {
                $sw.Dispose()
            }
        }
        finally {
            $fs.Dispose()
        }

        $lastRecordId = $e.RecordId

        Write-Output $line
    }

    Start-Sleep 2
}
