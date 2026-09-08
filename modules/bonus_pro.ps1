# ==============================
# SOC BONUS PRO MODULE
# Threat Intel + Auto Response
# ==============================

function Get-ThreatReputation($ip) {

    # Simulated threat intel
    if ($ip -like "10.*") {
        return "Internal Network"
    }
    elseif ($ip -like "172.*") {
        return "Known Scanner Activity"
    }
    elseif ($ip -like "192.168.*") {
        return "Suspicious LAN Actor"
    }
    else {
        return "Unknown Reputation"
    }
}

function Invoke-AutoResponse($ip, $risk) {

    if ($risk -eq "HIGH") {
        return "[AUTO-RESPONSE] Blocking IP $ip (simulated)"
    }

    return $null
}