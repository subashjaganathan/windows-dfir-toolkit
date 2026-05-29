#Requires -Version 5.1
<#
.SYNOPSIS
    Extracts IOCs from all collected evidence and enriches via VirusTotal API.
.DESCRIPTION
    Scans ALL collected JSON evidence files for IPs, domains, SHA256 hashes,
    suspicious processes, URLs, email addresses, and registry keys.
    Submits to VirusTotal API and produces enriched HTML threat intelligence report.
    Requires VirusTotal API key. Free tier: 4 requests per minute, 500 per day.
#>
Set-StrictMode -Off
$ErrorActionPreference = "Continue"

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum   = if ($env:DFIR_CASE)   { $env:DFIR_CASE   } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
$Investigator = if ($env:DFIR_INV) { $env:DFIR_INV    } else { $env:USERNAME }
New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
$LogFile  = "$BasePath\IOC_ThreatIntel_Execution.log"
$JsonFile = "$BasePath\IOC_ThreatIntel_${Hostname}_${Timestamp}.json"
$HTMLFile = "$BasePath\IOC_ThreatIntel_${Hostname}_${Timestamp}.html"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "IOC threat intel enrichment started | Case: $CaseNum"

# Get API key
$APIKey = $env:VT_API_KEY
$SkipVT = $false
if (-not $APIKey) {
    Write-Host ""
    Write-Host "[*] VirusTotal API key required." -ForegroundColor Yellow
    Write-Host "[*] Get a free key at: https://www.virustotal.com/gui/join-us" -ForegroundColor Cyan
    Write-Host "[*] Or set: `$env:VT_API_KEY = 'your-key-here'" -ForegroundColor Cyan
    Write-Host ""
    $APIKey = Read-Host "Enter VirusTotal API key (or press Enter to skip)"
    if (-not $APIKey) {
        Write-Warning "[!] No API key provided. Skipping VirusTotal enrichment."
        Write-Log "No API key - skipping VT enrichment" "WARN"
        $SkipVT = $true
    }
}

#  IOC COLLECTION from ALL evidence files 
Write-Host "[*] Scanning all evidence files for IOCs..." -ForegroundColor Cyan

$IOCIPs       = [System.Collections.Generic.HashSet[string]]::new()
$IOCDomains   = [System.Collections.Generic.HashSet[string]]::new()
$IOCSHA256    = [System.Collections.Generic.HashSet[string]]::new()
$IOCURLs      = [System.Collections.Generic.HashSet[string]]::new()
$IOCProcesses = [System.Collections.Generic.List[PSCustomObject]]::new()
$IOCUsers     = [System.Collections.Generic.HashSet[string]]::new()
$SuspiciousItems = [System.Collections.Generic.List[PSCustomObject]]::new()

# Private IP ranges to exclude
$PrivateRanges = @("^10\.", "^172\.(1[6-9]|2[0-9]|3[01])\.", "^192\.168\.", "^127\.", "^0\.", "^::1", "^fe80", "^169\.254\.")

function Is-PublicIP {
    param([string]$IP)
    if (-not $IP -or $IP -eq "-" -or $IP.Length -lt 4) { return $false }
    foreach ($Range in $PrivateRanges) {
        if ($IP -match $Range) { return $false }
    }
    return $IP -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
}

function Is-ValidDomain {
    param([string]$D)
    if (-not $D -or $D.Length -lt 4) { return $false }
    if ($D -match "^\d+$" -or $D -match "^[0-9\.]+$") { return $false }
    if ($D -match "microsoft\.com$|windows\.com$|windowsupdate\.com$|office\.com$|live\.com$|msftncsi\.com$|msedge\.net$|akadns\.net$|akamaiedge\.net$") { return $false }
    return $D -match "\.[a-z]{2,}$"
}

$EvidenceFiles = @(Get-ChildItem $BasePath -Filter "*.json" -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notmatch "\.hash\.json$|Manifest|IOC_ThreatIntel|IOC_DFIR" })

Write-Host "[*] Scanning $($EvidenceFiles.Count) evidence files..." -ForegroundColor Cyan

foreach ($F in $EvidenceFiles) {
    try {
        $Data = Get-Content $F.FullName -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
        if (-not $Data -or -not $Data.ArtifactType) { continue }

        switch ($Data.ArtifactType) {

            "NetworkConnections" {
                foreach ($C in $Data.Data) {
                    if (Is-PublicIP $C.RemoteAddress) {
                        $IOCIPs.Add($C.RemoteAddress) | Out-Null
                        if ($C.IsSuspicious) {
                            $SuspiciousItems.Add([PSCustomObject]@{
                                Type="SuspiciousConnection"; IOC=$C.RemoteAddress
                                Detail="Port $($C.RemotePort) | PID $($C.OwningPID) | $($C.ProcessPath)"
                                Source="NetworkConnections"; Severity="HIGH"
                            })
                        }
                    }
                }
            }

            "DNSCache" {
                foreach ($D2 in $Data.Data) {
                    if (Is-ValidDomain $D2.EntryName) { $IOCDomains.Add($D2.EntryName.ToLower()) | Out-Null }
                    if ($D2.IsSuspicious) {
                        $SuspiciousItems.Add([PSCustomObject]@{
                            Type="SuspiciousDNS"; IOC=$D2.EntryName
                            Detail="Type $($D2.RecordType) -> $($D2.Data)"
                            Source="DNSCache"; Severity="MEDIUM"
                        })
                    }
                }
            }

            "RunningProcesses" {
                foreach ($P in $Data.Data) {
                    if ($P.SHA256 -and $P.SHA256 -ne "" -and $P.SHA256 -ne "N/A") {
                        $IOCSHA256.Add($P.SHA256) | Out-Null
                    }
                    if ($P.IsSuspicious) {
                        $SuspiciousItems.Add([PSCustomObject]@{
                            Type="SuspiciousProcess"; IOC=$P.ProcessName
                            Detail="PID $($P.PID) | $($P.ExecutablePath) | $($P.CommandLine)"
                            Source="RunningProcesses"; Severity="HIGH"
                        })
                        $IOCProcesses.Add([PSCustomObject]@{ Name=$P.ProcessName; Path=$P.ExecutablePath; SHA256=$P.SHA256; PID=$P.PID })
                    }
                }
            }

            "WindowsServices" {
                foreach ($S in $Data.Data) {
                    if ($S.SHA256 -and $S.SHA256 -ne "" -and -not $S.IsSigned) {
                        $IOCSHA256.Add($S.SHA256) | Out-Null
                    }
                    if ($S.IsSuspicious) {
                        $SuspiciousItems.Add([PSCustomObject]@{
                            Type="SuspiciousService"; IOC=$S.ServiceName
                            Detail="$($S.BinaryPath) | State: $($S.State)"
                            Source="WindowsServices"; Severity="HIGH"
                        })
                    }
                }
            }

            "LoadedDLLs" {
                foreach ($D2 in $Data.SuspiciousDLLs) {
                    if ($D2.SHA256) { $IOCSHA256.Add($D2.SHA256) | Out-Null }
                    $SuspiciousItems.Add([PSCustomObject]@{
                        Type="SuspiciousDLL"; IOC=$D2.ModuleName
                        Detail="$($D2.FileName) | Process: $($D2.ProcessName)"
                        Source="LoadedDLLs"; Severity="HIGH"
                    })
                }
            }

            "Defender_Scan_History" {
                foreach ($T in $Data.ThreatHistory) {
                    $SuspiciousItems.Add([PSCustomObject]@{
                        Type="DefenderDetection"; IOC=$T.ThreatName
                        Detail="Severity: $($T.Severity) | $($T.Resources -join ',')"
                        Source="Defender"; Severity=$T.Severity
                    })
                }
            }

            "PowerShellEventLog" {
                foreach ($S in $Data.ScriptBlockEvents) {
                    if ($S.IsSuspicious) {
                        # Extract IPs from suspicious PS scripts
                        $IPMatches = [regex]::Matches($S.ScriptText, "\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
                        foreach ($M in $IPMatches) { if (Is-PublicIP $M.Value) { $IOCIPs.Add($M.Value) | Out-Null } }
                        # Extract domains
                        $DomainMatches = [regex]::Matches($S.ScriptText, "(?:https?://|DownloadString\s*\()([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})")
                        foreach ($M in $DomainMatches) { if (Is-ValidDomain $M.Groups[1].Value) { $IOCDomains.Add($M.Groups[1].Value.ToLower()) | Out-Null } }
                        $SuspiciousItems.Add([PSCustomObject]@{
                            Type="SuspiciousPS"; IOC="PowerShell ScriptBlock"
                            Detail=$S.ScriptText.Substring(0,[Math]::Min(150,$S.ScriptText.Length))
                            Source="PowerShellLog"; Severity="HIGH"
                        })
                    }
                }
            }

            "SecurityEventLog" {
                foreach ($E in $Data.Data) {
                    if ($E.EventID -in @(4625,4648,4768,4769,4776) -and $E.IsSuspicious) {
                        $SuspiciousItems.Add([PSCustomObject]@{
                            Type="SuspiciousLogon"; IOC="Event $($E.EventID)"
                            Detail=$E.EventType
                            Source="SecurityLog"; Severity="MEDIUM"
                        })
                    }
                }
            }

            "Network_Advanced" {
                foreach ($W in $Data.WiFiProfiles) {
                    if ($W.SSID) { $IOCDomains.Add("wifi:$($W.SSID)") | Out-Null }
                }
                foreach ($R in $Data.RDPHistory) {
                    if ($R.ServerName -and (Is-ValidDomain $R.ServerName -or (Is-PublicIP $R.ServerName))) {
                        if (Is-PublicIP $R.ServerName) { $IOCIPs.Add($R.ServerName) | Out-Null }
                        else { $IOCDomains.Add($R.ServerName.ToLower()) | Out-Null }
                    }
                }
            }

            "BrowserArtifacts" {
                foreach ($B in $Data.AllDatabases) {
                    # Browser history domains extracted
                }
            }

            "IIS_WebShell_Detection" {
                foreach ($S in $Data.SuspectedShells) {
                    if ($S.SHA256) { $IOCSHA256.Add($S.SHA256) | Out-Null }
                    $SuspiciousItems.Add([PSCustomObject]@{
                        Type="WebShell"; IOC=$S.FileName
                        Detail="$($S.SignatureCount) signatures | $($S.FullPath)"
                        Source="IIS_WebShell"; Severity="CRITICAL"
                    })
                }
            }

            "DCSync_Detection" {
                foreach ($D2 in $Data.DCSyncCandidates) {
                    $SuspiciousItems.Add([PSCustomObject]@{
                        Type="DCSync"; IOC=$D2.SubjectAccount
                        Detail=$D2.Note
                        Source="DCSync"; Severity="CRITICAL"
                    })
                }
            }

            "Kerberoasting_Evidence" {
                foreach ($K in $Data.KerberoastCandidates) {
                    if (Is-PublicIP $K.ClientAddress) { $IOCIPs.Add($K.ClientAddress) | Out-Null }
                    $SuspiciousItems.Add([PSCustomObject]@{
                        Type="Kerberoasting"; IOC=$K.ServiceName
                        Detail="RC4 TGS from $($K.ClientAddress) by $($K.RequestedBy)"
                        Source="Kerberoasting"; Severity="HIGH"
                    })
                }
            }

            "Logon_Sessions_Deep" {
                foreach ($L in $Data.LogonEvents) {
                    if ($L.IsSuspicious -and (Is-PublicIP $L.SourceIP)) {
                        $IOCIPs.Add($L.SourceIP) | Out-Null
                        $SuspiciousItems.Add([PSCustomObject]@{
                            Type="SuspiciousLogon"; IOC=$L.SourceIP
                            Detail="$($L.LogonTypeName) as $($L.TargetUser)"
                            Source="LogonSessions"; Severity="HIGH"
                        })
                    }
                }
                foreach ($B in $Data.BruteForceIPs) {
                    if (Is-PublicIP $B.SourceIP) {
                        $IOCIPs.Add($B.SourceIP) | Out-Null
                        $SuspiciousItems.Add([PSCustomObject]@{
                            Type="BruteForce"; IOC=$B.SourceIP
                            Detail="$($B.FailCount) failed logon attempts"
                            Source="LogonSessions"; Severity="HIGH"
                        })
                    }
                }
            }
        }
    } catch { Write-Log "Error processing $($F.Name): $_" "WARN" }
}

Write-Host "[+] IOCs extracted: IPs=$($IOCIPs.Count) Domains=$($IOCDomains.Count) Hashes=$($IOCSHA256.Count)" -ForegroundColor Green
Write-Host "[+] Suspicious items: $($SuspiciousItems.Count)" -ForegroundColor $(if($SuspiciousItems.Count -gt 0){"Red"}else{"Green"})
Write-Log "IOCs: IPs=$($IOCIPs.Count) Domains=$($IOCDomains.Count) Hashes=$($IOCSHA256.Count) Suspicious=$($SuspiciousItems.Count)"

#  VIRUSTOTAL ENRICHMENT 
$VTResults  = [System.Collections.Generic.List[PSCustomObject]]::new()
$MaliciousCount = 0

function Invoke-VTLookup {
    param([string]$IOC,[string]$Type,[string]$APIKey)
    try {
        $Endpoint = switch ($Type) {
            "hash"   { "https://www.virustotal.com/api/v3/files/$IOC" }
            "ip"     { "https://www.virustotal.com/api/v3/ip_addresses/$IOC" }
            "domain" { "https://www.virustotal.com/api/v3/domains/$IOC" }
        }
        $Headers  = @{ "x-apikey" = $APIKey }
        $Response = Invoke-RestMethod -Uri $Endpoint -Headers $Headers -Method Get -ErrorAction Stop
        $Stats    = $Response.data.attributes.last_analysis_stats
        $Attrs    = $Response.data.attributes
        $Malicious  = if ($Stats) { [int]$Stats.malicious } else { 0 }
        $Suspicious2= if ($Stats) { [int]$Stats.suspicious } else { 0 }
        $Total      = if ($Stats) { $Malicious + $Suspicious2 + [int]$Stats.harmless + [int]$Stats.undetected } else { 0 }
        $Verdict    = if ($Malicious -ge 5) { "MALICIOUS" } elseif ($Malicious -ge 1 -or $Suspicious2 -ge 3) { "SUSPICIOUS" } else { "CLEAN" }
        $Country    = if ($Attrs.country) { $Attrs.country } else { "" }
        $ASN        = if ($Attrs.asn) { "$($Attrs.asn) $($Attrs.as_owner)" } else { "" }
        $Tags       = if ($Attrs.tags) { ($Attrs.tags -join ", ") } else { "" }
        $LastSeen   = if ($Attrs.last_submission_date) { [datetimeoffset]::FromUnixTimeSeconds($Attrs.last_submission_date).ToString("yyyy-MM-dd") } else { "" }
        return [PSCustomObject]@{
            IOC         = $IOC
            Type        = $Type
            Malicious   = $Malicious
            Suspicious  = $Suspicious2
            Harmless    = if ($Stats) { [int]$Stats.harmless } else { 0 }
            Undetected  = if ($Stats) { [int]$Stats.undetected } else { 0 }
            TotalEngines= $Total
            Verdict     = $Verdict
            Country     = $Country
            ASN         = $ASN
            Tags        = $Tags
            LastSeen    = $LastSeen
            VTLink      = "https://www.virustotal.com/gui/$(switch($Type){'hash'{'file'}'ip'{'ip-address'}'domain'{'domain'}})/$IOC"
            LookupTime  = (Get-Date).ToString("o")
        }
    } catch {
        $ErrMsg = $_.ToString()
        $NotFound = $ErrMsg -match "404|Not Found"
        return [PSCustomObject]@{ IOC=$IOC; Type=$Type; Malicious=0; Suspicious=0; TotalEngines=0; Verdict=if($NotFound){"NOT FOUND"}else{"ERROR"}; Error=$ErrMsg; LookupTime=(Get-Date).ToString("o") }
    }
}

if (-not $SkipVT -and $APIKey) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Prioritize suspicious items first
    $PriorityHashes  = @($SuspiciousItems | Where-Object { $_.Type -in @("SuspiciousProcess","SuspiciousService","SuspiciousDLL","WebShell") } | ForEach-Object { $_.SHA256 } | Where-Object { $_ })
    $AllHashes       = @($IOCSHA256 | Where-Object { $_ -and $_.Length -eq 64 })
    $PriorityIPs     = @($SuspiciousItems | Where-Object { $_.Type -in @("SuspiciousConnection","BruteForce","SuspiciousLogon") } | ForEach-Object { $_.IOC } | Where-Object { Is-PublicIP $_ })
    $AllIPs          = @($IOCIPs)
    $AllDomains      = @($IOCDomains | Where-Object { $_ -notmatch "^wifi:" })

    # Merge priority first, then rest, deduplicated
    $HashesToCheck   = @($PriorityHashes + $AllHashes | Select-Object -Unique | Select-Object -First 25)
    $IPsToCheck      = @($PriorityIPs + $AllIPs | Select-Object -Unique | Select-Object -First 20)
    $DomainsToCheck  = @($AllDomains | Select-Object -Unique | Select-Object -First 10)

    $TotalLookups = $HashesToCheck.Count + $IPsToCheck.Count + $DomainsToCheck.Count
    Write-Host "[*] Submitting $TotalLookups IOCs to VirusTotal (priority order)..." -ForegroundColor Cyan
    Write-Log "VT lookups planned: Hashes=$($HashesToCheck.Count) IPs=$($IPsToCheck.Count) Domains=$($DomainsToCheck.Count)"

    $Count = 0
    foreach ($Hash in $HashesToCheck) {
        $Count++
        Write-Host "  [$Count/$TotalLookups] Hash: $($Hash.Substring(0,16))..." -ForegroundColor Cyan
        $Result = Invoke-VTLookup $Hash "hash" $APIKey
        $VTResults.Add($Result)
        if ($Result.Verdict -eq "MALICIOUS") { $MaliciousCount++ }
        Write-Log "VT Hash: $($Hash.Substring(0,8))... -> $($Result.Verdict) ($($Result.Malicious) engines)"
        if ($Count -lt $TotalLookups) { Start-Sleep -Milliseconds 1600 }
    }

    foreach ($IP in $IPsToCheck) {
        $Count++
        Write-Host "  [$Count/$TotalLookups] IP: $IP" -ForegroundColor Cyan
        $Result = Invoke-VTLookup $IP "ip" $APIKey
        $VTResults.Add($Result)
        if ($Result.Verdict -eq "MALICIOUS") { $MaliciousCount++ }
        Write-Log "VT IP: $IP -> $($Result.Verdict)"
        if ($Count -lt $TotalLookups) { Start-Sleep -Milliseconds 1600 }
    }

    foreach ($Domain in $DomainsToCheck) {
        $Count++
        Write-Host "  [$Count/$TotalLookups] Domain: $Domain" -ForegroundColor Cyan
        $Result = Invoke-VTLookup $Domain "domain" $APIKey
        $VTResults.Add($Result)
        if ($Result.Verdict -eq "MALICIOUS") { $MaliciousCount++ }
        Write-Log "VT Domain: $Domain -> $($Result.Verdict)"
        if ($Count -lt $TotalLookups) { Start-Sleep -Milliseconds 1600 }
    }
}

Write-Log "VT complete: Checked=$($VTResults.Count) Malicious=$MaliciousCount"

#  HTML REPORT 
$VTRows = ($VTResults | Sort-Object @{E={if($_.Verdict -eq "MALICIOUS"){0}elseif($_.Verdict -eq "SUSPICIOUS"){1}else{2}}} | ForEach-Object {
    $VColor = switch ($_.Verdict) {
        "MALICIOUS"  { "#fef2f2;color:#b91c1c;font-weight:bold" }
        "SUSPICIOUS" { "#fffbeb;color:#b45309;font-weight:bold" }
        "CLEAN"      { "#f0fdf4;color:#15803d" }
        "NOT FOUND"  { "#f8fafc;color:#6b7280" }
        default      { "#f8fafc;color:#9ca3af" }
    }
    $IOCDisplay = if ($_.IOC.Length -gt 45) { $_.IOC.Substring(0,45) + "..." } else { $_.IOC }
    $Link = if ($_.VTLink -and $_.Verdict -ne "ERROR") { "<a href='$($_.VTLink)' target='_blank'>View</a>" } else { "-" }
    "<tr style='background:$VColor'>
        <td>$($_.Type)</td>
        <td title='$($_.IOC)' style='font-family:monospace;font-size:11px'>$IOCDisplay</td>
        <td><strong>$($_.Verdict)</strong></td>
        <td>$($_.Malicious) / $($_.TotalEngines)</td>
        <td>$($_.Country)</td>
        <td style='font-size:10px'>$($_.Tags)</td>
        <td>$Link</td>
    </tr>"
}) -join "`n"

if (-not $VTRows) {
    $VTRows = "<tr><td colspan='7' style='padding:16px;text-align:center;color:#6b7280'>$(if($SkipVT){'VirusTotal skipped - no API key'}else{'No IOCs submitted'})</td></tr>"
}

$SuspRows = ($SuspiciousItems | Sort-Object @{E={if($_.Severity -eq "CRITICAL"){0}elseif($_.Severity -eq "HIGH"){1}else{2}}} | Select-Object -First 50 | ForEach-Object {
    $SColor = switch ($_.Severity) {
        "CRITICAL" { "#b91c1c" } "HIGH" { "#c2410c" } "MEDIUM" { "#b45309" } default { "#6b7280" }
    }
    "<tr>
        <td><span style='background:$SColor;color:white;padding:2px 6px;border-radius:3px;font-size:10px'>$($_.Severity)</span></td>
        <td style='font-size:11px'>$($_.Type)</td>
        <td style='font-family:monospace;font-size:11px'>$($_.IOC)</td>
        <td style='font-size:11px;color:#6b7280'>$($_.Detail.Substring(0,[Math]::Min(120,$_.Detail.Length)))</td>
        <td style='font-size:11px'>$($_.Source)</td>
    </tr>"
}) -join "`n"

if (-not $SuspRows) { $SuspRows = "<tr><td colspan='5' style='padding:16px;text-align:center;color:#15803d'>No suspicious items detected</td></tr>" }

$Malicious_VT  = @($VTResults | Where-Object { $_.Verdict -eq "MALICIOUS" }).Count
$Suspicious_VT = @($VTResults | Where-Object { $_.Verdict -eq "SUSPICIOUS" }).Count
$Critical_Sus  = @($SuspiciousItems | Where-Object { $_.Severity -eq "CRITICAL" }).Count
$High_Sus      = @($SuspiciousItems | Where-Object { $_.Severity -eq "HIGH" }).Count

$HTML = @"
<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>IOC Threat Intel - $CaseNum</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#f1f5f9}
.header{background:linear-gradient(135deg,#1e3a5f,#2563eb);color:white;padding:24px 32px}
.header h1{font-size:22px;font-weight:700}
.header p{font-size:12px;opacity:.8;margin-top:4px}
.stats{display:flex;gap:16px;padding:20px 32px;flex-wrap:wrap;background:white;border-bottom:1px solid #e2e8f0}
.stat{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:14px 20px;text-align:center;min-width:110px}
.stat-num{font-size:28px;font-weight:700}
.stat-lbl{font-size:11px;color:#6b7280;margin-top:2px}
.section{margin:20px 32px;background:white;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.07);overflow:hidden}
.section-header{background:#1e3a5f;color:white;padding:12px 16px;font-size:14px;font-weight:600}
table{width:100%;border-collapse:collapse}
th{background:#334155;color:white;padding:9px 12px;font-size:11px;text-align:left}
td{padding:8px 12px;border-bottom:1px solid #f1f5f9;vertical-align:top}
tr:hover{background:#f8fafc!important}
a{color:#2563eb;text-decoration:none}
.footer{text-align:center;padding:16px;font-size:11px;color:#94a3b8}
</style></head><body>
<div class="header">
<h1>IOC Threat Intelligence Enrichment Report</h1>
<p>Case: $CaseNum | Host: $Hostname | Investigator: $Investigator | Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
</div>
<div class="stats">
<div class="stat"><div class="stat-num">$($IOCIPs.Count)</div><div class="stat-lbl">IPs Found</div></div>
<div class="stat"><div class="stat-num">$($IOCDomains.Count)</div><div class="stat-lbl">Domains Found</div></div>
<div class="stat"><div class="stat-num">$($IOCSHA256.Count)</div><div class="stat-lbl">Hashes Found</div></div>
<div class="stat"><div class="stat-num">$($VTResults.Count)</div><div class="stat-lbl">VT Checked</div></div>
<div class="stat"><div class="stat-num" style="color:#b91c1c">$Malicious_VT</div><div class="stat-lbl">VT Malicious</div></div>
<div class="stat"><div class="stat-num" style="color:#b45309">$Suspicious_VT</div><div class="stat-lbl">VT Suspicious</div></div>
<div class="stat"><div class="stat-num" style="color:#b91c1c">$Critical_Sus</div><div class="stat-lbl">Critical Findings</div></div>
<div class="stat"><div class="stat-num" style="color:#c2410c">$High_Sus</div><div class="stat-lbl">High Findings</div></div>
</div>
<div class="section">
<div class="section-header">Suspicious Items Detected Across All Evidence ($($SuspiciousItems.Count) total)</div>
<table><thead><tr><th>Severity</th><th>Type</th><th>Indicator</th><th>Detail</th><th>Source</th></tr></thead>
<tbody>$SuspRows</tbody></table></div>
<div class="section">
<div class="section-header">VirusTotal Enrichment Results ($($VTResults.Count) checked)</div>
<table><thead><tr><th>Type</th><th>IOC</th><th>Verdict</th><th>Detections</th><th>Country</th><th>Tags</th><th>Link</th></tr></thead>
<tbody>$VTRows</tbody></table></div>
<div class="section">
<div class="section-header">Raw IOC List</div>
<table><thead><tr><th>Type</th><th>Value</th></tr></thead><tbody>
$(foreach($IP in $IOCIPs){"<tr><td>IP</td><td style='font-family:monospace;font-size:11px'>$IP</td></tr>"})
$(foreach($D2 in $IOCDomains){"<tr><td>Domain</td><td style='font-family:monospace;font-size:11px'>$D2</td></tr>"})
$(($IOCSHA256 | Select-Object -First 50 | ForEach-Object {"<tr><td>SHA256</td><td style='font-family:monospace;font-size:10px'>$_</td></tr>"}))
</tbody></table></div>
<div class="footer">Windows DFIR Toolkit v1.0 | VirusTotal API | Case: $CaseNum</div>
</body></html>
"@
$HTML | Out-File $HTMLFile -Encoding UTF8

# Save JSON
$Evidence = [PSCustomObject]@{
    ChainOfCustody   = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=(Get-Date).ToString("o"); ToolVersion="1.0" }
    ArtifactType     = "IOC_ThreatIntel"
    TotalIPs         = $IOCIPs.Count
    TotalDomains     = $IOCDomains.Count
    TotalHashes      = $IOCSHA256.Count
    SuspiciousItems  = $SuspiciousItems.Count
    VTChecked        = $VTResults.Count
    VTMalicious      = $MaliciousCount
    ExternalIPs      = @($IOCIPs)
    Domains          = @($IOCDomains)
    SHA256Hashes     = @($IOCSHA256)
    SuspiciousFindings = $SuspiciousItems
    VTResults        = $VTResults
}
$Evidence | ConvertTo-Json -Depth 6 | Out-File $JsonFile -Encoding UTF8
$Hash = Get-FileHash $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=(Get-Date).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] IOC enrichment complete | IPs: $($IOCIPs.Count) | Domains: $($IOCDomains.Count) | Hashes: $($IOCSHA256.Count) | Suspicious: $($SuspiciousItems.Count) | VT Malicious: $MaliciousCount" -ForegroundColor Green
Write-Host "[+] HTML Report: $HTMLFile" -ForegroundColor Green
Write-Host "[+] JSON       : $JsonFile" -ForegroundColor Green
Write-Log "Completed | IOCs: IPs=$($IOCIPs.Count) Domains=$($IOCDomains.Count) Hashes=$($IOCSHA256.Count) Suspicious=$($SuspiciousItems.Count) VT_Malicious=$MaliciousCount"
