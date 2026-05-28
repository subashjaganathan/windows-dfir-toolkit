#Requires -Version 5.1
<#
.SYNOPSIS
    Generates a professional HTML incident response report and IOC extract.

.DESCRIPTION
    Reads all JSON evidence files from C:\IR_Collection and produces:
    - A professional HTML dashboard with full findings
    - A structured text summary report
    - A JSON IOC extraction file (IPs, domains, hashes, users)
    - A CSV IOC file for SIEM import

.STANDARDS
    - NIST SP 800-61 Rev 2 (IR Report Format)
    - SANS IR Report Guidelines
    - ISO/IEC 27035 (Evidence Documentation)

.AUTHOR
    DFIR Toolkit

.VERSION
    1.0
#>

Set-StrictMode -Off
$ErrorActionPreference = "Continue"

$Timestamp    = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname     = $env:COMPUTERNAME
$BasePath     = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum      = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
$Investigator = if ($env:DFIR_INV)  { $env:DFIR_INV  } else { $env:USERNAME }
$ReportDir    = "$BasePath\Report_${Timestamp}"
New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null

$LogFile    = "$BasePath\Report_Execution.log"
$HTMLFile   = "$ReportDir\IR_Report_${Hostname}_${Timestamp}.html"
$TextReport = "$ReportDir\IR_Summary_${Hostname}_${Timestamp}.txt"
$IOCJson    = "$ReportDir\IOC_${Hostname}_${Timestamp}.json"
$IOCCsv     = "$ReportDir\IOC_${Hostname}_${Timestamp}.csv"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "Report generation started | Case: $CaseNum | Investigator: $Investigator"

#  Load Evidence Files 
Write-Host "[*] Loading evidence files from $BasePath ..." -ForegroundColor Cyan
$EvidenceFiles = @(Get-ChildItem $BasePath -Filter "*.json" -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notmatch "\.hash\.json$|Manifest|Report|IOC" })

$Evidence = [ordered]@{}
foreach ($F in $EvidenceFiles) {
    try {
        $Data = Get-Content $F.FullName -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
        if ($Data -and $Data.ArtifactType) {
            $Evidence[$Data.ArtifactType] = $Data
        }
    } catch {}
}
Write-Log "Loaded $($Evidence.Count) artifact types from $($EvidenceFiles.Count) files"
Write-Host "[*] Loaded $($Evidence.Count) artifact types" -ForegroundColor Cyan

#  Helper: safe count 
function Get-SafeCount {
    param($Obj)
    if ($null -eq $Obj) { return 0 }
    if ($Obj -is [System.Collections.ICollection]) { return $Obj.Count }
    if ($Obj -is [array]) { return $Obj.Count }
    return 1
}

#  Extract Metrics 
Write-Host "[*] Extracting metrics..." -ForegroundColor Cyan

$SysInfo   = $Evidence["SystemInformation"]
$ProcData  = $Evidence["RunningProcesses"]
$NetData   = $Evidence["NetworkConnections"]
$SvcData   = $Evidence["WindowsServices"]
$RegRun    = $Evidence["RegistryRunKeys"]
$Tasks     = $Evidence["ScheduledTasks"]
$WMIPers   = $Evidence["WMIPersistence"]
$THData    = $Evidence["ThreatHunting"]
$DeepPers  = $Evidence["Registry_Deep_Persistence"]
$CredData  = $Evidence["CredentialArtifacts"]
$USBData   = $Evidence["USB_Device_Driver_WER"]
$CertData  = $Evidence["CertificateStore"]
$PipeData  = $Evidence["NamedPipes"]
$DLLData   = $Evidence["LoadedDLLs"]
$UserData  = $Evidence["LocalUsersAndGroups"]
$DNSData   = $Evidence["DNSCache"]
$FirewallD = $Evidence["FirewallRules"]
$LMData    = $Evidence["LateralMovement"]

# System
$OSCaption   = if ($SysInfo) { $SysInfo.System.OSCaption }   else { "Unknown" }
$LastBoot    = if ($SysInfo) { $SysInfo.System.LastBootTime } else { "Unknown" }
$UptimeDays  = if ($SysInfo) { $SysInfo.System.UptimeDays }  else { "Unknown" }
$DomainName  = if ($SysInfo) { $SysInfo.Domain.DomainName }  else { "Unknown" }
$DomainRole  = if ($SysInfo) { $SysInfo.Domain.DomainRole }  else { "Unknown" }
$TotalRAM    = if ($SysInfo) { "$($SysInfo.System.TotalRAMGB) GB" } else { "Unknown" }

# Process counts
$TotalProcs    = if ($ProcData) { $ProcData.ProcessCount }   else { 0 }
$UnsignedProcs = if ($ProcData) { @($ProcData.Data | Where-Object { $_.SignatureStatus -and $_.SignatureStatus -notin @("Valid","Unknown") -and $_.ExecutablePath -ne "Access Denied" }).Count } else { 0 }

# Network
$TotalConns = if ($NetData) { $NetData.ConnectionCount } else { 0 }
$ExtConns   = if ($NetData) { @($NetData.Data | Where-Object { $_.RemoteAddress -and $_.RemoteAddress -notmatch "^(0\.0\.0\.0|127\.|::1|$)" -and $_.State -eq "Established" }).Count } else { 0 }

# Services
$TotalSvcs    = if ($SvcData)  { $SvcData.ServiceCount } else { 0 }
$UnsignedSvcs = if ($SvcData)  { @($SvcData.Data | Where-Object { $_.SignatureStatus -and $_.SignatureStatus -notin @("Valid","Unknown") }).Count } else { 0 }

# Persistence
$RunKeyCount  = if ($RegRun)  { $RegRun.EntryCount }    else { 0 }
$TaskCount    = if ($Tasks)   { $Tasks.TaskCount }       else { 0 }
$WMISubCount  = if ($WMIPers) { $WMIPers.EntryCount }   else { 0 }

# Threat indicators
$COMHijacks   = if ($THData)   { Get-SafeCount $THData.COMHijackCandidates }  else { 0 }
$LOLBASHits   = if ($THData)   { Get-SafeCount $THData.LOLBASHits }           else { 0 }
$DefExclCount = if ($THData)   { (Get-SafeCount $THData.DefenderExclusions.ExclusionPath) + (Get-SafeCount $THData.DefenderExclusions.ExclusionProcess) } else { 0 }
$UACDisabled  = if ($THData)   { $THData.UACConfig.UACDisabled }               else { $false }

# Deep persistence
$CritPers     = if ($DeepPers) { $DeepPers.CriticalFindings } else { 0 }
$HighPers     = if ($DeepPers) { $DeepPers.HighFindings }     else { 0 }

# Credentials
$WDigest      = if ($CredData) { $CredData.LSASSProtection.WDigestEnabled } else { $null }
$WDigestRisk  = ($WDigest -eq 1)
$LSASSProtected = if ($CredData) { $CredData.LSASSProtection.RunAsPPL -eq 1 } else { $false }
$CredMgrCount = if ($CredData) { Get-SafeCount $CredData.CredentialManager } else { 0 }

# USB
$USBCount     = if ($USBData) { Get-SafeCount $USBData.USBStorHistory }      else { 0 }
$UnsignedDrvs = if ($USBData) { $USBData.UnsignedRunningDrivers }            else { 0 }
$WERCount     = if ($USBData) { Get-SafeCount $USBData.WERCrashReports }     else { 0 }

# Certs
$RogueCerts   = if ($CertData) { $CertData.RogueRootCount }                  else { 0 }

# Pipes / DLLs
$SuspPipes    = if ($PipeData) { $PipeData.SuspiciousCount }                  else { 0 }
$SuspDLLs     = if ($DLLData)  { $DLLData.SuspiciousCount }                   else { 0 }

# Lateral movement
$SMBSessions  = if ($LMData)  { Get-SafeCount $LMData.SMBSessions }           else { 0 }
$OpenShares   = if ($LMData)  { Get-SafeCount $LMData.NetworkShares }         else { 0 }

# Firewall
$FWRuleCount  = if ($FirewallD) { $FirewallD.RuleCount }                       else { 0 }

#  Risk Scoring 
$RiskScore = 0
$RiskFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-Risk {
    param([string]$Category, [string]$Finding, [string]$Severity, [int]$Score, [string]$Recommendation)
    $script:RiskScore += $Score
    $script:RiskFindings.Add([PSCustomObject]@{
        Category       = $Category
        Finding        = $Finding
        Severity       = $Severity
        Score          = $Score
        Recommendation = $Recommendation
        MITRERef       = ""
    })
}

if ($WDigestRisk)      { Add-Risk "Credential Access" "WDigest authentication enabled - plaintext credentials stored in LSASS memory" "CRITICAL" 40 "Disable WDigest: Set HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential to 0" }
if ($CritPers -gt 0)   { Add-Risk "Persistence" "$CritPers critical persistence mechanism(s) detected (IFEO/SSP/AppCert DLL)" "CRITICAL" 35 "Investigate and remove unauthorized registry persistence entries immediately" }
if ($RogueCerts -gt 0) { Add-Risk "Defense Evasion" "$RogueCerts unauthorized root certificate(s) installed" "CRITICAL" 30 "Remove unauthorized certificates from Trusted Root Certification Authorities store" }
if ($UnsignedDrvs -gt 0){ Add-Risk "Defense Evasion" "$UnsignedDrvs unsigned kernel driver(s) running" "HIGH" 25 "Investigate unsigned drivers - potential rootkit or malicious driver" }
if ($LOLBASHits -gt 0) { Add-Risk "Execution" "$LOLBASHits LOLBAS binary abuse event(s) in event logs" "HIGH" 20 "Review event logs for context around each LOLBAS execution" }
if ($COMHijacks -gt 0) { Add-Risk "Persistence" "$COMHijacks COM hijacking candidate(s) in HKCU" "HIGH" 20 "Review HKCU\Software\Classes\CLSID for unauthorized entries" }
if ($UACDisabled)      { Add-Risk "Privilege Escalation" "UAC is disabled - no elevation barrier for attackers" "HIGH" 20 "Re-enable UAC via Group Policy or registry" }
if ($SuspPipes -gt 10) { Add-Risk "Command and Control" "$SuspPipes suspicious named pipe(s) detected matching C2 patterns" "HIGH" 15 "Investigate named pipes matching known C2 framework patterns" }
if ($UnsignedProcs -gt 0){ Add-Risk "Execution" "$UnsignedProcs unsigned process executable(s) running" "MEDIUM" 10 "Investigate unsigned processes particularly those in user-writable paths" }
if ($DefExclCount -gt 0){ Add-Risk "Defense Evasion" "$DefExclCount Defender exclusion(s) configured" "MEDIUM" 10 "Verify all Defender exclusions are legitimate and authorized" }
if ($HighPers -gt 0)   { Add-Risk "Persistence" "$HighPers high-risk persistence entry(s) found in deep registry scan" "MEDIUM" 10 "Review SSP packages, time providers, port monitors and logon scripts" }
if ($SuspDLLs -gt 5)   { Add-Risk "Defense Evasion" "$SuspDLLs suspicious DLL(s) loaded from writable or non-standard paths" "MEDIUM" 10 "Investigate DLLs loaded from TEMP/AppData/Downloads into system processes" }
if (-not $LSASSProtected){ Add-Risk "Credential Access" "LSASS is not running as Protected Process (PPL disabled)" "LOW" 5 "Enable RunAsPPL to protect LSASS from memory dumps" }
if ($WMISubCount -gt 0) { Add-Risk "Persistence" "$WMISubCount WMI event subscription(s) active" "LOW" 5 "Review all WMI subscriptions for unauthorized entries" }

$RiskLevel = if ($RiskScore -ge 60) { "CRITICAL" } elseif ($RiskScore -ge 30) { "HIGH" } elseif ($RiskScore -ge 10) { "MEDIUM" } else { "LOW" }
$RiskColor = switch ($RiskLevel) { "CRITICAL"{"#b91c1c"} "HIGH"{"#c2410c"} "MEDIUM"{"#b45309"} default{"#15803d"} }

#  IOC Extraction 
Write-Host "[*] Extracting IOCs..." -ForegroundColor Cyan
$IOCIPs      = [System.Collections.Generic.HashSet[string]]::new()
$IOCDomains  = [System.Collections.Generic.HashSet[string]]::new()
$IOCSHA256   = [System.Collections.Generic.HashSet[string]]::new()
$IOCUsers    = [System.Collections.Generic.HashSet[string]]::new()

if ($NetData)   { $NetData.Data  | Where-Object { $_.RemoteAddress -and $_.RemoteAddress -notmatch "^(0\.0\.0\.0|127\.|::1|^$)" } | ForEach-Object { $IOCIPs.Add($_.RemoteAddress) | Out-Null } }
if ($ProcData)  { $ProcData.Data | Where-Object { $_.SHA256 } | ForEach-Object { $IOCSHA256.Add($_.SHA256) | Out-Null } }
if ($SvcData)   { $SvcData.Data  | Where-Object { $_.SHA256 } | ForEach-Object { $IOCSHA256.Add($_.SHA256) | Out-Null } }
if ($DNSData)   { $DNSData.Data  | Where-Object { $_.EntryName -and $_.EntryName -notmatch "^(\d{1,3}\.){3}\d{1,3}$" } | ForEach-Object { $IOCDomains.Add($_.EntryName) | Out-Null } }
if ($UserData)  { $UserData.Users | Where-Object { $_.Enabled -and $_.UserName -notin @("Administrator","DefaultAccount","Guest","WDAGUtilityAccount") } | ForEach-Object { $IOCUsers.Add($_.UserName) | Out-Null } }

$IOCData = [PSCustomObject]@{
    CaseNumber    = $CaseNum
    Hostname      = $Hostname
    GeneratedAt   = (Get-Date).ToString("o")
    Investigator  = $Investigator
    ExternalIPs   = @($IOCIPs)
    Domains       = @($IOCDomains)
    SHA256Hashes  = @($IOCSHA256)
    LocalUsers    = @($IOCUsers)
    TotalIOCs     = $IOCIPs.Count + $IOCDomains.Count + $IOCSHA256.Count
}
$IOCData | ConvertTo-Json -Depth 4 | Out-File $IOCJson -Encoding UTF8

# CSV for SIEM
$IOCCsvRows = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($IP in $IOCIPs)     { $IOCCsvRows.Add([PSCustomObject]@{ Type="IP"; Value=$IP; Source="NetworkConnections"; Case=$CaseNum }) }
foreach ($D  in $IOCDomains) { $IOCCsvRows.Add([PSCustomObject]@{ Type="Domain"; Value=$D; Source="DNSCache"; Case=$CaseNum }) }
foreach ($H  in $IOCSHA256)  { $IOCCsvRows.Add([PSCustomObject]@{ Type="SHA256"; Value=$H; Source="Processes/Services"; Case=$CaseNum }) }
$IOCCsvRows | Export-Csv $IOCCsv -NoTypeInformation -Encoding UTF8

Write-Log "IOCs extracted: IPs=$($IOCIPs.Count) Domains=$($IOCDomains.Count) Hashes=$($IOCSHA256.Count)"

#  HTML Report 
Write-Host "[*] Generating professional HTML report..." -ForegroundColor Cyan

$GenDate = Get-Date -Format "dd MMMM yyyy HH:mm:ss"

# Build risk findings table rows
$RiskTableRows = ($RiskFindings | ForEach-Object {
    $SevColor = switch ($_.Severity) {
        "CRITICAL" { "background:#fef2f2;border-left:4px solid #b91c1c" }
        "HIGH"     { "background:#fff7ed;border-left:4px solid #c2410c" }
        "MEDIUM"   { "background:#fffbeb;border-left:4px solid #b45309" }
        default    { "background:#f0fdf4;border-left:4px solid #15803d" }
    }
    $SevBadge = switch ($_.Severity) {
        "CRITICAL" { "<span style='background:#b91c1c;color:white;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:bold'>CRITICAL</span>" }
        "HIGH"     { "<span style='background:#c2410c;color:white;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:bold'>HIGH</span>" }
        "MEDIUM"   { "<span style='background:#b45309;color:white;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:bold'>MEDIUM</span>" }
        default    { "<span style='background:#15803d;color:white;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:bold'>LOW</span>" }
    }
    "<tr style='$SevColor'><td style='padding:10px 12px'>$($_.Category)</td><td style='padding:10px 12px'>$($_.Finding)</td><td style='padding:10px 12px;text-align:center'>$SevBadge</td><td style='padding:10px 12px;font-size:12px;color:#6b7280'>$($_.Recommendation)</td></tr>"
}) -join "`n"

if (-not $RiskFindings.Count) {
    $RiskTableRows = "<tr><td colspan='4' style='padding:16px;text-align:center;color:#6b7280'>No significant risk findings detected</td></tr>"
}

# Build artifact table
$ArtifactRows = ($Evidence.Keys | Sort-Object | ForEach-Object {
    $D     = $Evidence[$_]
    $Count = if ($D.EntryCount)      { $D.EntryCount }
             elseif ($D.ProcessCount){ $D.ProcessCount }
             elseif ($D.ConnectionCount){ $D.ConnectionCount }
             elseif ($D.ServiceCount){ $D.ServiceCount }
             elseif ($D.TaskCount)   { $D.TaskCount }
             elseif ($D.RuleCount)   { $D.RuleCount }
             else { "-" }
    $Collected = if ($D.ChainOfCustody.CollectedAt) { $D.ChainOfCustody.CollectedAt -replace "T"," " -replace "\.\d+.*","" } else { "-" }
    "<tr><td style='padding:8px 12px;font-size:13px'>$_</td><td style='padding:8px 12px;text-align:center'><span style='color:#15803d;font-weight:bold'>Collected</span></td><td style='padding:8px 12px;text-align:center;font-size:13px'>$Count</td><td style='padding:8px 12px;font-size:12px;color:#6b7280'>$Collected</td></tr>"
}) -join "`n"

# Network connections table (top 20 established external)
$NetTableRows = ""
if ($NetData) {
    $ExtConnList = @($NetData.Data | Where-Object { $_.RemoteAddress -and $_.RemoteAddress -notmatch "^(0\.0\.0\.0|127\.|::1|^$)" -and $_.State -eq "Established" } | Select-Object -First 20)
    $NetTableRows = ($ExtConnList | ForEach-Object {
        "<tr><td style='padding:7px 12px;font-size:12px'>$($_.ProcessName)</td><td style='padding:7px 12px;font-size:12px'>$($_.PID)</td><td style='padding:7px 12px;font-size:12px'>$($_.LocalAddress):$($_.LocalPort)</td><td style='padding:7px 12px;font-size:12px;color:#b91c1c;font-weight:bold'>$($_.RemoteAddress)</td><td style='padding:7px 12px;font-size:12px'>$($_.RemotePort)</td><td style='padding:7px 12px;font-size:12px'>$($_.State)</td></tr>"
    }) -join "`n"
    if (-not $NetTableRows) { $NetTableRows = "<tr><td colspan='6' style='padding:12px;text-align:center;color:#6b7280'>No established external connections found</td></tr>" }
}

# Running processes - unsigned ones
$ProcTableRows = ""
if ($ProcData) {
    $UnsignedProcList = @($ProcData.Data | Where-Object { $_.SignatureStatus -and $_.SignatureStatus -notin @("Valid","Unknown") -and $_.ExecutablePath -ne "Access Denied" } | Select-Object -First 20)
    $ProcTableRows = ($UnsignedProcList | ForEach-Object {
        "<tr><td style='padding:7px 12px;font-size:12px'>$($_.ProcessName)</td><td style='padding:7px 12px;font-size:12px'>$($_.PID)</td><td style='padding:7px 12px;font-size:12px;color:#b91c1c'>$($_.SignatureStatus)</td><td style='padding:7px 12px;font-size:12px;word-break:break-all'>$($_.ExecutablePath)</td><td style='padding:7px 12px;font-size:11px;font-family:monospace'>$(if($_.SHA256){$_.SHA256.Substring(0,16)+'...'}else{'-'})</td></tr>"
    }) -join "`n"
    if (-not $ProcTableRows) { $ProcTableRows = "<tr><td colspan='5' style='padding:12px;text-align:center;color:#6b7280'>No unsigned processes detected</td></tr>" }
}

# USB History table
$USBTableRows = ""
if ($USBData) {
    $USBList = @($USBData.USBStorHistory | Select-Object -First 15)
    $USBTableRows = ($USBList | ForEach-Object {
        "<tr><td style='padding:7px 12px;font-size:12px'>$($_.FriendlyName)</td><td style='padding:7px 12px;font-size:12px'>$($_.SerialNumber)</td><td style='padding:7px 12px;font-size:12px'>$($_.Manufacturer)</td><td style='padding:7px 12px;font-size:12px'>$($_.DeviceType)</td></tr>"
    }) -join "`n"
    if (-not $USBTableRows) { $USBTableRows = "<tr><td colspan='4' style='padding:12px;text-align:center;color:#6b7280'>No USB storage devices found in history</td></tr>" }
}

# Persistence entries
$PersTableRows = ""
if ($RegRun) {
    $PersList = @($RegRun.Data | Select-Object -First 15)
    $PersTableRows = ($PersList | ForEach-Object {
        "<tr><td style='padding:7px 12px;font-size:12px'>$($_.ValueName)</td><td style='padding:7px 12px;font-size:12px;word-break:break-all'>$($_.Command)</td><td style='padding:7px 12px;font-size:11px;color:#6b7280;word-break:break-all'>$($_.RegistryPath -replace 'HKEY_LOCAL_MACHINE','HKLM' -replace 'HKEY_CURRENT_USER','HKCU')</td></tr>"
    }) -join "`n"
    if (-not $PersTableRows) { $PersTableRows = "<tr><td colspan='3' style='padding:12px;text-align:center;color:#6b7280'>No run key entries found</td></tr>" }
}

# Risk findings deep persistence
$DeepPersRows = ""
if ($DeepPers -and $DeepPers.PersistenceFindings) {
    $DeepList = @($DeepPers.PersistenceFindings | Select-Object -First 15)
    $DeepPersRows = ($DeepList | ForEach-Object {
        $SevColor = if ($_.RiskLevel -eq "CRITICAL") { "color:#b91c1c;font-weight:bold" } else { "color:#c2410c" }
        "<tr><td style='padding:7px 12px;font-size:12px'>$($_.Category)</td><td style='padding:7px 12px;font-size:12px;$SevColor'>$($_.RiskLevel)</td><td style='padding:7px 12px;font-size:12px;word-break:break-all'>$($_.Value)</td></tr>"
    }) -join "`n"
    if (-not $DeepPersRows) { $DeepPersRows = "<tr><td colspan='3' style='padding:12px;text-align:center;color:#6b7280'>No deep persistence findings</td></tr>" }
}

# Summary stat boxes
function Get-StatBox {
    param([string]$Label, $Value, [string]$Color="#1e3a5f", [bool]$Alert=$false)
    $BG = if ($Alert) { "#fef2f2" } else { "#f8fafc" }
    $TC = if ($Alert) { "#b91c1c" } else { $Color }
    "<div style='background:$BG;border:1px solid #e2e8f0;border-radius:6px;padding:16px;text-align:center;min-width:100px'><div style='font-size:28px;font-weight:bold;color:$TC'>$Value</div><div style='font-size:12px;color:#64748b;margin-top:4px'>$Label</div></div>"
}

$StatBoxes = @(
    (Get-StatBox "Running Processes"   $TotalProcs)
    (Get-StatBox "Unsigned Processes"  $UnsignedProcs  "#b91c1c" ($UnsignedProcs -gt 0))
    (Get-StatBox "Network Connections" $TotalConns)
    (Get-StatBox "External Connections" $ExtConns       "#b91c1c" ($ExtConns -gt 5))
    (Get-StatBox "Services"            $TotalSvcs)
    (Get-StatBox "Unsigned Services"   $UnsignedSvcs   "#b91c1c" ($UnsignedSvcs -gt 0))
    (Get-StatBox "USB Devices (Ever)"  $USBCount       "#b45309" ($USBCount -gt 3))
    (Get-StatBox "Risk Score"          "$RiskScore/100" $RiskColor $true)
) -join "`n"

# Write HTML
$HTML = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Incident Response Report - $CaseNum</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', Arial, sans-serif; background: #f1f5f9; color: #1e293b; font-size: 14px; }

  .page-header { background: #1e3a5f; color: white; padding: 0; }
  .header-top  { background: #0f2744; padding: 12px 40px; display:flex; justify-content:space-between; align-items:center; }
  .header-top .org { font-size:12px; opacity:0.7; letter-spacing:1px; text-transform:uppercase; }
  .header-main { padding: 28px 40px 24px; }
  .header-main h1 { font-size: 26px; font-weight: 600; letter-spacing: 0.5px; }
  .header-main .subtitle { font-size: 13px; opacity: 0.75; margin-top: 6px; }

  .meta-bar { background: #162d4a; padding: 14px 40px; display: flex; gap: 32px; flex-wrap: wrap; }
  .meta-item { display: flex; flex-direction: column; }
  .meta-label { font-size: 10px; text-transform: uppercase; letter-spacing: 1px; opacity: 0.6; }
  .meta-value { font-size: 13px; font-weight: 500; margin-top: 2px; }

  .risk-banner { padding: 16px 40px; background: $RiskColor; color: white; display: flex; align-items: center; gap: 16px; }
  .risk-banner .risk-label { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; opacity: 0.85; }
  .risk-banner .risk-value { font-size: 22px; font-weight: 700; }
  .risk-banner .risk-desc  { font-size: 13px; opacity: 0.9; }

  .container { max-width: 1400px; margin: 0 auto; padding: 28px 40px; }

  .section { background: white; border-radius: 8px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); overflow: hidden; }
  .section-header { background: #f8fafc; border-bottom: 1px solid #e2e8f0; padding: 14px 20px; display: flex; align-items: center; gap: 10px; }
  .section-header h2 { font-size: 15px; font-weight: 600; color: #1e3a5f; }
  .section-badge { background: #1e3a5f; color: white; font-size: 11px; padding: 2px 8px; border-radius: 10px; }
  .section-body { padding: 20px; }

  .stat-grid { display: flex; flex-wrap: wrap; gap: 12px; }

  table { width: 100%; border-collapse: collapse; }
  th { background: #1e3a5f; color: white; padding: 10px 12px; text-align: left; font-size: 12px; font-weight: 500; letter-spacing: 0.5px; text-transform: uppercase; }
  td { border-bottom: 1px solid #f1f5f9; vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: #f8fafc; }

  .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }
  .three-col { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; }

  .info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
  .info-item { padding: 8px 12px; background: #f8fafc; border-radius: 4px; border-left: 3px solid #1e3a5f; }
  .info-item .key { font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; }
  .info-item .val { font-size: 13px; font-weight: 500; margin-top: 2px; }

  .ioc-box { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 16px; }
  .ioc-count { font-size: 32px; font-weight: bold; color: #1e3a5f; }
  .ioc-label { font-size: 12px; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; }

  .footer { background: #1e3a5f; color: white; padding: 20px 40px; margin-top: 32px; display: flex; justify-content: space-between; align-items: center; font-size: 12px; opacity: 0.9; }

  @media print {
    body { background: white; }
    .container { padding: 0; }
  }
</style>
</head>
<body>

<div class="page-header">
  <div class="header-top">
    <span class="org">Windows DFIR Toolkit v1.0 - Confidential Incident Response Report</span>
    <span style="font-size:12px;opacity:0.6">RESTRICTED - LAW ENFORCEMENT / IR TEAM ONLY</span>
  </div>
  <div class="header-main">
    <h1>Incident Response Investigation Report</h1>
    <div class="subtitle">Digital Forensics Evidence Collection and Analysis Summary</div>
  </div>
  <div class="meta-bar">
    <div class="meta-item"><span class="meta-label">Case Number</span><span class="meta-value">$CaseNum</span></div>
    <div class="meta-item"><span class="meta-label">Investigator</span><span class="meta-value">$Investigator</span></div>
    <div class="meta-item"><span class="meta-label">Host Examined</span><span class="meta-value">$Hostname</span></div>
    <div class="meta-item"><span class="meta-label">Operating System</span><span class="meta-value">$OSCaption</span></div>
    <div class="meta-item"><span class="meta-label">Domain</span><span class="meta-value">$DomainName ($DomainRole)</span></div>
    <div class="meta-item"><span class="meta-label">Report Generated</span><span class="meta-value">$GenDate</span></div>
    <div class="meta-item"><span class="meta-label">Last Boot Time</span><span class="meta-value">$LastBoot</span></div>
    <div class="meta-item"><span class="meta-label">System Uptime</span><span class="meta-value">$UptimeDays days</span></div>
  </div>
</div>

<div class="risk-banner">
  <div>
    <div class="risk-label">Overall Risk Assessment</div>
    <div class="risk-value">$RiskLevel</div>
  </div>
  <div style="width:1px;height:40px;background:rgba(255,255,255,0.3)"></div>
  <div>
    <div class="risk-label">Risk Score</div>
    <div class="risk-value">$RiskScore / 100</div>
  </div>
  <div style="width:1px;height:40px;background:rgba(255,255,255,0.3)"></div>
  <div class="risk-desc">Based on $($RiskFindings.Count) findings across $($Evidence.Count) collected artifact categories. Findings require investigation by a qualified IR analyst.</div>
</div>

<div class="container">

  <!-- Summary Statistics -->
  <div class="section">
    <div class="section-header"><h2>Executive Summary - Key Metrics</h2></div>
    <div class="section-body">
      <div class="stat-grid">$StatBoxes</div>
    </div>
  </div>

  <!-- Risk Findings -->
  <div class="section">
    <div class="section-header">
      <h2>Risk Findings</h2>
      <span class="section-badge">$($RiskFindings.Count) findings</span>
    </div>
    <div class="section-body" style="padding:0">
      <table>
        <tr><th style="width:160px">Category</th><th>Finding</th><th style="width:100px;text-align:center">Severity</th><th style="width:320px">Recommendation</th></tr>
        $RiskTableRows
      </table>
    </div>
  </div>

  <!-- System Information -->
  <div class="section">
    <div class="section-header"><h2>System Information</h2></div>
    <div class="section-body">
      <div class="info-grid">
        <div class="info-item"><div class="key">Hostname</div><div class="val">$Hostname</div></div>
        <div class="info-item"><div class="key">Operating System</div><div class="val">$OSCaption</div></div>
        <div class="info-item"><div class="key">Domain</div><div class="val">$DomainName</div></div>
        <div class="info-item"><div class="key">Domain Role</div><div class="val">$DomainRole</div></div>
        <div class="info-item"><div class="key">Total RAM</div><div class="val">$TotalRAM</div></div>
        <div class="info-item"><div class="key">Uptime</div><div class="val">$UptimeDays days</div></div>
        <div class="info-item"><div class="key">Last Boot</div><div class="val">$LastBoot</div></div>
        <div class="info-item"><div class="key">WDigest Status</div><div class="val" style="color:$(if($WDigestRisk){'#b91c1c'}else{'#15803d'})">$(if($WDigestRisk){'ENABLED - CRITICAL RISK'}else{'Disabled (Secure)'})</div></div>
        <div class="info-item"><div class="key">LSASS PPL Protection</div><div class="val" style="color:$(if($LSASSProtected){'#15803d'}else{'#b45309'})">$(if($LSASSProtected){'Enabled (Protected)'}else{'Not Enabled'})</div></div>
        <div class="info-item"><div class="key">UAC Status</div><div class="val" style="color:$(if($UACDisabled){'#b91c1c'}else{'#15803d'})">$(if($UACDisabled){'DISABLED - HIGH RISK'}else{'Enabled'})</div></div>
      </div>
    </div>
  </div>

  <!-- Network Connections -->
  <div class="section">
    <div class="section-header">
      <h2>Active Network Connections - External Established</h2>
      <span class="section-badge">$ExtConns external</span>
    </div>
    <div class="section-body" style="padding:0">
      <table>
        <tr><th>Process</th><th>PID</th><th>Local Address</th><th>Remote Address</th><th>Remote Port</th><th>State</th></tr>
        $NetTableRows
      </table>
    </div>
  </div>

  <!-- Unsigned Processes -->
  <div class="section">
    <div class="section-header">
      <h2>Unsigned / Suspicious Processes</h2>
      <span class="section-badge">$UnsignedProcs unsigned</span>
    </div>
    <div class="section-body" style="padding:0">
      <table>
        <tr><th>Process Name</th><th>PID</th><th>Signature Status</th><th>Executable Path</th><th>SHA256 (truncated)</th></tr>
        $ProcTableRows
      </table>
    </div>
  </div>

  <!-- Persistence -->
  <div class="two-col">
    <div class="section">
      <div class="section-header">
        <h2>Registry Run Key Entries</h2>
        <span class="section-badge">$RunKeyCount entries</span>
      </div>
      <div class="section-body" style="padding:0">
        <table>
          <tr><th>Value Name</th><th>Command</th><th>Registry Path</th></tr>
          $PersTableRows
        </table>
      </div>
    </div>
    <div class="section">
      <div class="section-header">
        <h2>Deep Registry Persistence Findings</h2>
        <span class="section-badge">$($CritPers + $HighPers) findings</span>
      </div>
      <div class="section-body" style="padding:0">
        <table>
          <tr><th>Category</th><th>Risk Level</th><th>Value</th></tr>
          $DeepPersRows
        </table>
      </div>
    </div>
  </div>

  <!-- USB Devices -->
  <div class="section">
    <div class="section-header">
      <h2>USB Device Connection History</h2>
      <span class="section-badge">$USBCount devices ever connected</span>
    </div>
    <div class="section-body" style="padding:0">
      <table>
        <tr><th>Friendly Name</th><th>Serial Number</th><th>Manufacturer</th><th>Device Type</th></tr>
        $USBTableRows
      </table>
    </div>
  </div>

  <!-- IOC Summary -->
  <div class="section">
    <div class="section-header"><h2>Indicators of Compromise (IOC) Summary</h2></div>
    <div class="section-body">
      <div class="three-col">
        <div class="ioc-box"><div class="ioc-count">$($IOCIPs.Count)</div><div class="ioc-label">Unique External IP Addresses</div></div>
        <div class="ioc-box"><div class="ioc-count">$($IOCDomains.Count)</div><div class="ioc-label">DNS Cache Domain Entries</div></div>
        <div class="ioc-box"><div class="ioc-count">$($IOCSHA256.Count)</div><div class="ioc-count" style="font-size:14px;color:#64748b">File SHA256 Hashes</div></div>
      </div>
      <div style="margin-top:16px;padding:12px;background:#f8fafc;border-radius:6px;font-size:13px;color:#64748b">
        IOC files exported to: <strong>$IOCJson</strong> (JSON) and <strong>$IOCCsv</strong> (CSV for SIEM import)
      </div>
    </div>
  </div>

  <!-- Evidence Collection Summary -->
  <div class="section">
    <div class="section-header">
      <h2>Evidence Collection Summary</h2>
      <span class="section-badge">$($Evidence.Count) artifact types</span>
    </div>
    <div class="section-body" style="padding:0">
      <table>
        <tr><th>Artifact Type</th><th style="text-align:center">Status</th><th style="text-align:center">Record Count</th><th>Collection Time</th></tr>
        $ArtifactRows
      </table>
    </div>
  </div>

  <!-- Chain of Custody -->
  <div class="section">
    <div class="section-header"><h2>Chain of Custody</h2></div>
    <div class="section-body">
      <div class="info-grid">
        <div class="info-item"><div class="key">Case Number</div><div class="val">$CaseNum</div></div>
        <div class="info-item"><div class="key">Investigator</div><div class="val">$Investigator</div></div>
        <div class="info-item"><div class="key">Collection Host</div><div class="val">$Hostname</div></div>
        <div class="info-item"><div class="key">Report Generated</div><div class="val">$GenDate</div></div>
        <div class="info-item"><div class="key">Evidence Location</div><div class="val">$BasePath</div></div>
        <div class="info-item"><div class="key">Toolkit Version</div><div class="val">Windows DFIR Toolkit v1.0</div></div>
        <div class="info-item"><div class="key">Standards Applied</div><div class="val">NIST SP 800-61 Rev2, SANS PICERL, ISO/IEC 27035, MITRE ATT&amp;CK</div></div>
        <div class="info-item"><div class="key">Evidence Integrity</div><div class="val">SHA256 hash stored per artifact file</div></div>
      </div>
    </div>
  </div>

</div>

<div class="footer">
  <div>Windows DFIR Toolkit v1.0 | Case: $CaseNum | Generated: $GenDate</div>
  <div>CONFIDENTIAL - FOR AUTHORIZED INVESTIGATORS ONLY</div>
</div>

</body>
</html>
"@

$HTML | Out-File $HTMLFile -Encoding UTF8
Write-Log "HTML report written: $HTMLFile"

#  Text Summary 
Write-Host "[*] Generating text summary report..." -ForegroundColor Cyan

$FindingsText = ($RiskFindings | ForEach-Object {
    "  [$($_.Severity)] $($_.Category): $($_.Finding)`n    Action: $($_.Recommendation)"
}) -join "`n`n"

if (-not $FindingsText) { $FindingsText = "  No significant findings detected." }

$TextReportContent = @"
================================================================================
         INCIDENT RESPONSE INVESTIGATION REPORT
         Windows DFIR Toolkit v1.0
================================================================================
CASE NUMBER     : $CaseNum
INVESTIGATOR    : $Investigator
HOST EXAMINED   : $Hostname
OPERATING SYSTEM: $OSCaption
DOMAIN          : $DomainName ($DomainRole)
REPORT GENERATED: $GenDate
STANDARDS       : NIST SP 800-61 Rev2, SANS PICERL, ISO 27035, MITRE ATT&CK
================================================================================

OVERALL RISK ASSESSMENT: $RiskLevel (Score: $RiskScore / 100)

================================================================================
SYSTEM BASELINE
================================================================================
  Last Boot Time    : $LastBoot
  System Uptime     : $UptimeDays days
  Total RAM         : $TotalRAM
  WDigest Status    : $(if($WDigestRisk){'ENABLED - CRITICAL: Plaintext credentials in LSASS memory'}else{'Disabled (Secure)'})
  LSASS PPL         : $(if($LSASSProtected){'Protected (RunAsPPL Enabled)'}else{'Not Protected'})
  UAC Status        : $(if($UACDisabled){'DISABLED - HIGH RISK'}else{'Enabled'})

================================================================================
KEY FINDINGS ($($RiskFindings.Count) total)
================================================================================
$FindingsText

================================================================================
ARTIFACT SUMMARY
================================================================================
  Artifact Types Collected : $($Evidence.Count)
  Running Processes        : $TotalProcs ($UnsignedProcs unsigned)
  Network Connections      : $TotalConns ($ExtConns external established)
  Windows Services         : $TotalSvcs ($UnsignedSvcs unsigned)
  Registry Run Keys        : $RunKeyCount
  Scheduled Tasks          : $TaskCount
  WMI Subscriptions        : $WMISubCount
  USB Devices (History)    : $USBCount
  WER Crash Reports        : $WERCount
  Unsigned Drivers Running : $UnsignedDrvs
  Rogue Root Certificates  : $RogueCerts
  Suspicious Named Pipes   : $SuspPipes
  Suspicious DLLs          : $SuspDLLs
  Credential Manager Entries: $CredMgrCount
  SMB Sessions             : $SMBSessions
  Network Shares           : $OpenShares
  Firewall Rules           : $FWRuleCount
  COM Hijack Candidates    : $COMHijacks
  LOLBAS Event Log Hits    : $LOLBASHits
  Defender Exclusions      : $DefExclCount

================================================================================
INDICATOR OF COMPROMISE (IOC) SUMMARY
================================================================================
  External IP Addresses    : $($IOCIPs.Count)
  DNS Cache Domains        : $($IOCDomains.Count)
  File SHA256 Hashes       : $($IOCSHA256.Count)
  Active User Accounts     : $($IOCUsers.Count)

  IOC JSON Export          : $IOCJson
  IOC CSV Export (SIEM)    : $IOCCsv

================================================================================
OUTPUT FILES
================================================================================
  Evidence Directory       : $BasePath
  HTML Report              : $HTMLFile
  Text Summary             : $TextReport
  IOC JSON                 : $IOCJson
  IOC CSV                  : $IOCCsv

================================================================================
CHAIN OF CUSTODY DECLARATION
================================================================================
  I, $Investigator, certify that this report was generated using Windows DFIR
  Toolkit v3.0 on $GenDate. All evidence files have been preserved with
  SHA256 integrity hashes. Collection was performed in a read-only, forensically
  sound manner consistent with NIST SP 800-86 guidelines.
================================================================================
  END OF REPORT
================================================================================
"@

$TextReportContent | Out-File $TextReport -Encoding UTF8

Write-Host "[+] Report generation complete" -ForegroundColor Green
Write-Host "[+] HTML Report   : $HTMLFile"  -ForegroundColor Green
Write-Host "[+] Text Summary  : $TextReport" -ForegroundColor Green
Write-Host "[+] IOC JSON      : $IOCJson"    -ForegroundColor Green
Write-Host "[+] IOC CSV       : $IOCCsv"     -ForegroundColor Green
Write-Host "[+] Risk Level    : $RiskLevel (Score: $RiskScore/100)" -ForegroundColor $(if($RiskLevel -eq "CRITICAL"){"Red"} elseif($RiskLevel -eq "HIGH"){"Yellow"} else{"Green"})
Write-Log "Report completed | Risk: $RiskLevel ($RiskScore) | Findings: $($RiskFindings.Count) | IOCs: $($IOCData.TotalIOCs)"
