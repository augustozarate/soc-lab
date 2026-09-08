$base = "C:\soc-lab"
New-Item -ItemType Directory -Force -Path "$base\logs" | Out-Null

$path = "C:\soc-lab\logs\stream.jsonl"

while ($true) {

    $events = Get-WinEvent -FilterHashtable @{
        LogName='Security'
        ID=4625
        StartTime=(Get-Date).AddSeconds(-2)
    } -ErrorAction SilentlyContinue

    foreach ($e in $events) {

        # Extraer IP real
        $ip = $e.Properties[19].Value

        if (!$ip -or $ip -eq "-" -or $ip -eq "::1") {
            continue
        }

        $obj = @{
            time = (Get-Date -Format "HH:mm:ss")
            level = "HIGH"
            ip = $ip
            message = "FAILED LOGIN"
        }

        $line = $obj | ConvertTo-Json -Compress

        # ======================================
        # SHARED WRITE (FIX WSL PERMISSION ERROR)
        # ======================================

        $fs = [System.IO.File]::Open(
            $path,
            [System.IO.FileMode]::Append,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::ReadWrite
        )

        $sw = New-Object System.IO.StreamWriter($fs)
        $sw.WriteLine($line)
        $sw.Flush()
        $sw.Close()
        $fs.Close()

        Write-Output $line
    }

    Start-Sleep 2
}