# ==========================================
# SOC LIVE MONITOR
# ==========================================

Clear-Host

$projectRoot = (
    Resolve-Path (
        Join-Path $PSScriptRoot ".."
    )
).Path

$logsDir = Join-Path `
    $projectRoot `
    "logs"

$snapshotFile = Join-Path `
    $logsDir `
    "monitor_snapshot.json"


function Get-SocStatus(
    $summary
) {

    if (
        $summary.high_or_critical -gt 0 `
        -or $summary.max_incident_risk -ge 80
    ) {
        return "RED"
    }

    if (
        $summary.total_incidents -gt 0 `
        -or $summary.max_incident_risk -ge 50
    ) {
        return "YELLOW"
    }

    return "GREEN"
}


function Get-StatusColor(
    $status
) {

    switch ($status) {

        "RED" {
            return "Red"
        }

        "YELLOW" {
            return "Yellow"
        }

        default {
            return "Green"
        }
    }
}


while ($true) {

    Clear-Host

    Write-Host `
        "========= SOC LIVE MONITOR =========" `
        -ForegroundColor Cyan

    if (!(Test-Path $snapshotFile)) {

        Write-Host ""
        Write-Host `
            "Waiting for SOC snapshot..." `
            -ForegroundColor Yellow

        Start-Sleep 2
        continue
    }

    try {

        $snapshot = (
            Get-Content `
                $snapshotFile `
                -Raw `
            | ConvertFrom-Json
        )

    }
    catch {

        Write-Host ""
        Write-Host `
            "Snapshot read failed. Retrying..." `
            -ForegroundColor Yellow

        Start-Sleep 1
        continue
    }

    $summary = $snapshot.summary

    $socStatus = Get-SocStatus(
        $summary
    )

    $statusColor = Get-StatusColor(
        $socStatus
    )

    Write-Host ""
    Write-Host "SOC STATUS: " -NoNewline

    Write-Host `
        $socStatus `
        -ForegroundColor $statusColor

    Write-Host ""
    Write-Host "SUMMARY" `
        -ForegroundColor Cyan

    Write-Host (
        "Incidents: {0}" `
        -f $summary.total_incidents
    )

    Write-Host (
        "High/Critical: {0}" `
        -f $summary.high_or_critical
    )

    Write-Host (
        "UEBA incidents: {0}" `
        -f $summary.ueba_incidents
    )

    Write-Host (
        "Campaigns: {0}" `
        -f $summary.total_campaigns
    )

    Write-Host (
        "Max incident risk: {0}" `
        -f $summary.max_incident_risk
    )

    Write-Host ""
    Write-Host `
        "ACTIVE INCIDENTS" `
        -ForegroundColor Yellow

    Write-Host ""

    $incidents = @($snapshot.incidents)

    if ($incidents.Count -eq 0) {
        Write-Host "No incidents."
    }
    else {

        $visibleIncidents = $incidents |
            Select-Object -First 10

        foreach ($incident in $visibleIncidents) {

            $technique = $incident.technique_id

            if (!$technique) {
                $technique = "-"
            }

            $alerts = $incident.alert_types -join ","

            if (!$alerts) {
                $alerts = "-"
            }

            Write-Host (
                "{0} | {1} | Risk:{2} | {3} | {4}" -f `
                    $incident.ip,
                    $incident.severity,
                    $incident.risk_score,
                    $technique,
                    $alerts
            )

            Write-Host (
                "   Status:{0} | Reputation:{1} | Campaign:{2}" -f `
                    $incident.status,
                    $incident.threat_reputation,
                    $incident.campaign_id
            )
        }
    }

    Write-Host ""
    Write-Host `
        "CAMPAIGNS" `
        -ForegroundColor Magenta

    Write-Host ""

    $campaigns = @($snapshot.campaigns)

    if ($campaigns.Count -eq 0) {
        Write-Host "No campaigns."
    }
    else {

        $visibleCampaigns = $campaigns |
            Select-Object -First 5

        foreach ($campaign in $visibleCampaigns) {

            $tactics = $campaign.tactics -join ","

            if (!$tactics) {
                $tactics = "-"
            }

            Write-Host (
                "{0} | Stage:{1} | Risk:{2} | Incidents:{3}" -f `
                    $campaign.id,
                    $campaign.stage,
                    $campaign.risk,
                    $campaign.incident_count
            )

            Write-Host (
                "   Tactics: {0}" -f $tactics
            )
        }
    }

    Write-Host ""
    Write-Host (
        "Snapshot: {0}" `
        -f $snapshot.generated_at
    ) `
    -ForegroundColor DarkGray

    Start-Sleep 2
}
