#Requires -Version 5.1
<#
.SYNOPSIS
    Enriches collected IOCs against VirusTotal API.
.DESCRIPTION
    Reads IOC JSON from previous collection, submits hashes and IPs
    to VirusTotal API, and produces an enriched threat intelligence report.
    Requires a VirusTotal API key (free tier: 4 requests/minute).
    Set $env:VT_API_KEY before running, or enter when prompted.
#>
Set-StrictMode -Off
$ErrorActionPreference = "Continue"

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
$LogFile  = "$BasePath\IOC_ThreatIntel_Execution.log"
$JsonFile = "$BasePath\IOC_ThreatIntel_${Hostname}_${Timestamp}.json"
$HTMLFile = "$BasePath\IOC_ThreatIntel_${Hostname}_${Timestamp}.html"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "IOC threat intel enrichment started | Case: $CaseNum"

# Get API key
$APIKey = $env:VT_API_KEY
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

# Load existing IOC file
Write-Host "[*] Loading IOC data from previous collection..." -ForegroundColor Cyan
$IOCFiles = @(Get-ChildItem $BasePath -Filter "IOC_*.json" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1)

$IOCData = $null
if ($IOCFiles) {
    try { $IOCData = Get-Content $IOCFiles[0].FullName -Raw | ConvertFrom-Json } catch {}
}

if (-not $IOCData) {
    Write-Warning "[!] No IOC file found. Run main collection first."
    Write-Log "No IOC file found" "WARN"
    $IOCData = [PSCustomObject]@{
        ExternalIPs  = @()
        SHA256Hashes = @()
        Domains      = @()
    }
}

Write-Log "IOCs loaded: IPs=$($IOCData.ExternalIPs.Count) Hashes=$($IOCData.SHA256Hashes.Count) Domains=$($IOCData.Domains.Count)"

$VTResults  = [System.Collections.Generic.List[PSCustomObject]]::new()
$MaliciousCount = 0

function Invoke-VTLookup {
    param([string]$IOC, [string]$Type, [string]$APIKey)
    try {
        $Endpoint = switch ($Type) {
            "hash"   { "https://www.virustotal.com/api/v3/files/$IOC" }
            "ip"     { "https://www.virustotal.com/api/v3/ip_addresses/$IOC" }
            "domain" { "https://www.virustotal.com/api/v3/domains/$IOC" }
        }
        $Headers  = @{ "x-apikey" = $APIKey }
        $Response = Invoke-RestMethod -Uri $Endpoint -Headers $Headers -Method Get -ErrorAction Stop
        $Stats    = $Response.data.attributes.last_analysis_stats
        $Malicious= if ($Stats) { $Stats.malicious } else { 0 }
        $Suspicious = if ($Stats) { $Stats.suspicious } else { 0 }
        return [PSCustomObject]@{
            IOC            = $IOC
            Type           = $Type
            Malicious      = $Malicious
            Suspicious     = $Suspicious
            Harmless       = if ($Stats) { $Stats.harmless } else { 0 }
            Undetected     = if ($Stats) { $Stats.undetected } else { 0 }
            TotalEngines   = if ($Stats) { $Stats.malicious + $Stats.suspicious + $Stats.harmless + $Stats.undetected } else { 0 }
            Verdict        = if ($Malicious -ge 5) { "MALICIOUS" } elseif ($Malicious -ge 1) { "SUSPICIOUS" } else { "CLEAN" }
            VTLink         = "https://www.virustotal.com/gui/$(switch($Type){'hash'{'file'}'ip'{'ip-address'}'domain'{'domain'}})/$IOC"
            LookupTime     = (Get-Date).ToString("o")
        }
    } catch {
        return [PSCustomObject]@{ IOC=$IOC; Type=$Type; Error=$_.ToString(); Verdict="ERROR" }
    }
}

if (-not $SkipVT -and $APIKey) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Limit to avoid rate limiting (free tier = 4/min = 500/day)
    $MaxIPs     = [Math]::Min($IOCData.ExternalIPs.Count, 20)
    $MaxHashes  = [Math]::Min($IOCData.SHA256Hashes.Count, 20)
    $MaxDomains = [Math]::Min($IOCData.Domains.Count, 10)

    Write-Host "[*] Submitting $MaxHashes hashes to VirusTotal (rate limited)..." -ForegroundColor Cyan
    Write-Log "VT lookups: Hashes=$MaxHashes IPs=$MaxIPs Domains=$MaxDomains"

    $Count = 0
    foreach ($Hash in ($IOCData.SHA256Hashes | Select-Object -First $MaxHashes)) {
        Write-Host "  [*] Hash $($Count+1)/$MaxHashes : $($Hash.Substring(0,16))..." -ForegroundColor Cyan
        $Result = Invoke-VTLookup $Hash "hash" $APIKey
        $VTResults.Add($Result)
        if ($Result.Verdict -eq "MALICIOUS") { $MaliciousCount++ }
        Write-Log "VT Hash: $Hash -> $($Result.Verdict) ($($Result.Malicious) detections)"
        $Count++
        if ($Count -lt $MaxHashes) { Start-Sleep -Milliseconds 1500 }  # Rate limit
    }

    Write-Host "[*] Submitting $MaxIPs IPs to VirusTotal..." -ForegroundColor Cyan
    $Count = 0
    foreach ($IP in ($IOCData.ExternalIPs | Select-Object -First $MaxIPs)) {
        Write-Host "  [*] IP $($Count+1)/$MaxIPs : $IP" -ForegroundColor Cyan
        $Result = Invoke-VTLookup $IP "ip" $APIKey
        $VTResults.Add($Result)
        if ($Result.Verdict -eq "MALICIOUS") { $MaliciousCount++ }
        Write-Log "VT IP: $IP -> $($Result.Verdict)"
        $Count++
        if ($Count -lt $MaxIPs) { Start-Sleep -Milliseconds 1500 }
    }

    Write-Host "[*] Submitting $MaxDomains domains to VirusTotal..." -ForegroundColor Cyan
    $Count = 0
    foreach ($Domain in ($IOCData.Domains | Select-Object -First $MaxDomains)) {
        Write-Host "  [*] Domain $($Count+1)/$MaxDomains : $Domain" -ForegroundColor Cyan
        $Result = Invoke-VTLookup $Domain "domain" $APIKey
        $VTResults.Add($Result)
        if ($Result.Verdict -eq "MALICIOUS") { $MaliciousCount++ }
        Write-Log "VT Domain: $Domain -> $($Result.Verdict)"
        $Count++
        if ($Count -lt $MaxDomains) { Start-Sleep -Milliseconds 1500 }
    }
}

Write-Log "VT enrichment complete: Total=$($VTResults.Count) Malicious=$MaliciousCount"

# HTML Report
$VTRows = ($VTResults | ForEach-Object {
    $VerdictColor = switch ($_.Verdict) {
        "MALICIOUS"  { "background:#fef2f2;color:#b91c1c;font-weight:bold" }
        "SUSPICIOUS" { "background:#fffbeb;color:#b45309;font-weight:bold" }
        "CLEAN"      { "background:#f0fdf4;color:#15803d" }
        default      { "color:#6b7280" }
    }
    $Link = if ($_.VTLink) { "<a href='$($_.VTLink)' target='_blank' style='color:#1e3a5f'>View on VT</a>" } else { "-" }
    "<tr>
        <td style='padding:8px 12px;font-size:12px;font-family:monospace'>$($_.IOC.Substring(0,[Math]::Min(40,$_.IOC.Length)))</td>
        <td style='padding:8px 12px;font-size:12px'>$($_.Type)</td>
        <td style='padding:8px 12px;font-size:12px;$VerdictColor'>$($_.Verdict)</td>
        <td style='padding:8px 12px;font-size:12px'>$($_.Malicious) / $($_.TotalEngines)</td>
        <td style='padding:8px 12px;font-size:12px'>$Link</td>
    </tr>"
}) -join "`n"

if (-not $VTRows) {
    $VTRows = "<tr><td colspan='5' style='padding:16px;text-align:center;color:#6b7280'>$(if($SkipVT){'VirusTotal lookup skipped - no API key provided'}else{'No IOCs submitted'})</td></tr>"
}

$HTMLContent = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>IOC Threat Intelligence - $CaseNum</title>
<style>
  body{font-family:'Segoe UI',Arial,sans-serif;background:#f1f5f9;margin:0}
  .header{background:#1e3a5f;color:white;padding:20px 32px}
  .header h1{font-size:20px;margin:0}
  .header p{font-size:12px;opacity:0.75;margin:4px 0 0}
  .container{padding:24px 32px}
  .card{background:white;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,0.08);overflow:hidden;margin-bottom:20px}
  .card-header{background:#f8fafc;border-bottom:1px solid #e2e8f0;padding:12px 16px}
  .card-header h2{font-size:15px;font-weight:600;color:#1e3a5f;margin:0}
  table{width:100%;border-collapse:collapse}
  th{background:#1e3a5f;color:white;padding:10px 12px;text-align:left;font-size:11px;text-transform:uppercase}
  td{border-bottom:1px solid #f1f5f9;vertical-align:top}
  .stats{display:flex;gap:16px;padding:16px;flex-wrap:wrap}
  .stat{background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:12px 16px;text-align:center;min-width:100px}
  .stat-num{font-size:24px;font-weight:bold;color:#1e3a5f}
  .stat-lbl{font-size:11px;color:#6b7280}
  .footer{text-align:center;padding:16px;font-size:12px;color:#94a3b8}
</style>
</head>
<body>
<div class="header">
  <h1>IOC Threat Intelligence Enrichment Report</h1>
  <p>Case: $CaseNum | Host: $Hostname | Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Source: VirusTotal API</p>
</div>
<div class="container">
  <div class="card">
    <div class="stats">
      <div class="stat"><div class="stat-num">$($VTResults.Count)</div><div class="stat-lbl">IOCs Checked</div></div>
      <div class="stat"><div class="stat-num" style="color:#b91c1c">$MaliciousCount</div><div class="stat-lbl">Malicious</div></div>
      <div class="stat"><div class="stat-num" style="color:#b45309">$(@($VTResults|Where-Object{$_.Verdict -eq 'SUSPICIOUS'}).Count)</div><div class="stat-lbl">Suspicious</div></div>
      <div class="stat"><div class="stat-num" style="color:#15803d">$(@($VTResults|Where-Object{$_.Verdict -eq 'CLEAN'}).Count)</div><div class="stat-lbl">Clean</div></div>
    </div>
  </div>
  <div class="card">
    <div class="card-header"><h2>VirusTotal Results</h2></div>
    <table>
      <tr><th>IOC</th><th>Type</th><th>Verdict</th><th>Detections</th><th>Link</th></tr>
      $VTRows
    </table>
  </div>
</div>
<div class="footer">Windows DFIR Toolkit v1.0 | VirusTotal API | Case: $CaseNum</div>
</body>
</html>
"@
$HTMLContent | Out-File $HTMLFile -Encoding UTF8

$Evidence = [PSCustomObject]@{
    ChainOfCustody = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=(Get-Date).ToString("o"); ToolVersion="1.0" }
    ArtifactType   = "IOC_ThreatIntel"
    TotalLookups   = $VTResults.Count
    MaliciousCount = $MaliciousCount
    APIKeyProvided = [bool]$APIKey
    Results        = $VTResults
}

$Evidence | ConvertTo-Json -Depth 5 | Out-File $JsonFile -Encoding UTF8
$Hash = Get-FileHash $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=(Get-Date).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] IOC enrichment complete | Checked: $($VTResults.Count) | Malicious: $MaliciousCount" -ForegroundColor Green
Write-Host "[+] HTML Report: $HTMLFile" -ForegroundColor Green
Write-Host "[+] JSON       : $JsonFile" -ForegroundColor Green
Write-Log "Completed"
