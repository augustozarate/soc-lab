Clear-Host

Write-Host `
    "=== STARTING SOC LAB ===" `
    -ForegroundColor Cyan

$root = (
    Resolve-Path (
        Join-Path $PSScriptRoot ".."
    )
).Path

$wslOutput = & wsl.exe --exec `
    wslpath -a -u $root

$wslExitCode = $LASTEXITCODE

if ($wslExitCode -ne 0) {
    throw (
        "Unable to resolve project path in WSL. " +
        "wslpath exit code: $wslExitCode"
    )
}

$wslRoot = (
    $wslOutput |
    Out-String
).Trim()

if (
    !$wslRoot `
    -or !$wslRoot.StartsWith("/")
) {
    throw (
        "Invalid WSL project path: " +
        "'$wslRoot'"
    )
}

$engineScript = (
    "$wslRoot/scripts/run_engine.sh"
)

$monitorDir = Join-Path `
    $root `
    "monitor"

# ---------- ENGINE (WSL) ----------

Write-Host "Launching SOC Engine..."

Start-Process wt.exe `
    -ArgumentList @(
        "wsl",
        "bash",
        $engineScript
    )

# ---------- MONITOR ----------

Write-Host "Launching SOC Monitor..."

Start-Process pwsh `
    -ArgumentList @(
        "-NoExit",
        "-Command",
        "Set-Location '$monitorDir'; ./soc_monitor.ps1"
    )

Write-Host ""

Write-Host `
    "SOC LAB RUNNING" `
    -ForegroundColor Green
