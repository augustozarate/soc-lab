# Load SOC Bonus PRO modules
$modulePath = "$PSScriptRoot\..\modules\bonus_pro.ps1"

if (Test-Path $modulePath) {
    . $modulePath
}
else {
    Write-Host "[WARN] Bonus PRO module not loaded" -ForegroundColor Yellow
}

Clear-Host

$base = "$PSScriptRoot\..\logs"

$attackersFile = "$base\attackers.json"
$eventsFile = "$base\events.json"
$alertsFile = "$base\data\alerts.json"

function Get-Risk($score) {
    if ($score -gt 150) { return "HIGH" }
    elseif ($score -gt 60) { return "MEDIUM" }
    else { return "LOW" }
}

while ($true) {

    Clear-Host
    Write-Host "========= SOC LIVE MONITOR v5 =========" -ForegroundColor Cyan

    if (!(Test-Path $attackersFile)) {
        Write-Host "Waiting for SOC engine..."
        Start-Sleep 2
        continue
    }

    $attackers = Get-Content $attackersFile | ConvertFrom-Json

    $globalRisk = "GREEN"

    Write-Host ""
    Write-Host "ACTIVE THREATS" -ForegroundColor Yellow
    Write-Host ""

    foreach ($ip in $attackers.PSObject.Properties.Name) {

    	$a = $attackers.$ip
    	$risk = Get-Risk $a.score

    	# ===== BONUS PRO =====
    	$reputation = Get-ThreatReputation $ip
    	$response = Invoke-AutoResponse $ip $risk
    	# =====================

    	if ($risk -eq "HIGH") { $globalRisk = "RED" }
    	elseif ($risk -eq "MEDIUM" -and $globalRisk -ne "RED") {
        	$globalRisk = "YELLOW"
    	}

    	$tech = ($a.techniques -join ",")

    	Write-Host "$ip | Score:$($a.score) | Risk:$risk | Status:$($a.status) | Techniques:$tech"

    	Write-Host "   Intel: $reputation" -ForegroundColor Cyan

    	if ($response) {
        	Write-Host "   $response" -ForegroundColor Red
    	}
     }
    Write-Host ""
    Write-Host "SOC STATUS: $globalRisk" -ForegroundColor Green
    Write-Host ""

    # last events (visual only)
    if (Test-Path $eventsFile) {
        Write-Host "LAST EVENTS"
        Get-Content $eventsFile -Tail 8
    }
    
    if (Test-Path $alertsFile) {
    	Write-Host ""
    	Write-Host "ACTIVE ALERTS" -ForegroundColor Red
    	Get-Content $alertsFile -Tail 6
    }

    if (Test-Path $alertsFile) {
    	Write-Host ""
    	Write-Host "UEBA ALERTS" -ForegroundColor Red
    	Get-Content $alertsFile -Tail 6
    }

    Start-Sleep 2
}