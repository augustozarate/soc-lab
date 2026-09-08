Clear-Host
Write-Host "=== STARTING SOC LAB ===" -ForegroundColor Cyan

$root = "C:\soc-lab"

# ---------- ENGINE (WSL) ----------
Write-Host "Launching SOC Engine..."

Start-Process wt.exe `
    -ArgumentList "wsl /mnt/c/soc-lab/scripts/run_engine.sh"

# ---------- MONITOR ----------
Write-Host "Launching SOC Monitor..."

Start-Process pwsh `
    -ArgumentList "-NoExit", "-Command", "Set-Location '$root\monitor'; ./soc_monitor.ps1"

Write-Host ""
Write-Host "SOC LAB RUNNING" -ForegroundColor Green