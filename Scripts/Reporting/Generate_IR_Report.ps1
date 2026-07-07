#Requires -Version 5.1
<#
.SYNOPSIS
    Generates a professional HTML incident response report.
.DESCRIPTION
    Reads all JSON evidence files and produces a detailed
    professional HTML report with full findings, risk scoring,
    MITRE ATT&CK mapping, IOC extraction, and chain of custody.
.STANDARDS
    NIST SP 800-61 Rev 2, SANS PICERL, ISO/IEC 27035, MITRE ATT&CK v15
.VERSION
    1.0
#>
Set-StrictMode -Off
$ErrorActionPreference = "Continue"

$Timestamp    = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname     = $env:COMPUTERNAME
$BasePath     = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum      = if ($env:DFIR_CASE)   { $env:DFIR_CASE   } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
$Investigator = if ($env:DFIR_INV)    { $env:DFIR_INV    } else { $env:USERNAME }
$ReportDir    = "$BasePath\Report_${Timestamp}"
New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null

$LogFile    = "$BasePath\Report_Execution.log"
$HTMLFile   = "$ReportDir\IR_Report_${Hostname}_${Timestamp}.html"
$TextReport = "$ReportDir\IR_Summary_${Hostname}_${Timestamp}.txt"
$IOCJson    = "$ReportDir\IOC_${Hostname}_${Timestamp}.json"
$IOCCsv     = "$ReportDir\IOC_${Hostname}_${Timestamp}.csv"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "Report generation started | Case: $CaseNum | Investigator: $Investigator"

# Load Evidence
Write-Host "[*] Loading evidence files from $BasePath ..." -ForegroundColor Cyan
$EvidenceFiles = @(Get-ChildItem $BasePath -Filter "*.json" -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notmatch "\.hash\.json$|Manifest|Report|IOC" })

$Evidence = [ordered]@{}
foreach ($F in $EvidenceFiles) {
    try {
        $Data = Get-Content $F.FullName -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
        if ($Data -and $Data.ArtifactType) { $Evidence[$Data.ArtifactType] = $Data }
    } catch {}
}
Write-Log "Loaded $($Evidence.Count) artifact types"
Write-Host "[*] Loaded $($Evidence.Count) artifact types" -ForegroundColor Cyan

function Get-Safe { param($V, $Default="-") if ($null -ne $V -and $V.ToString() -ne "") { $V.ToString() } else { $Default } }
function Get-SafeCount { param($O) if ($null -eq $O) { return 0 } if ($O -is [System.Collections.ICollection] -or $O -is [array]) { return $O.Count } return 1 }

# Load all evidence objects
$SysInfo   = $Evidence["SystemInformation"]
$ProcData  = $Evidence["RunningProcesses"]
$NetData   = $Evidence["NetworkConnections"]
$SvcData   = $Evidence["WindowsServices"]
$RegRun    = $Evidence["RegistryRunKeys"]
$Tasks     = $Evidence["ScheduledTasks"]
$TasksXML  = $Evidence["ScheduledTaskXML"]
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
$PSLog     = $Evidence["PowerShellEventLog"]
$SecLog    = $Evidence["SecurityEventLog"]
$DefData   = $Evidence["Defender_Scan_History"]
$AVData    = $Evidence["AV_EDR_Status"]
$BrowData  = $Evidence["BrowserArtifacts"]
$CloudData = $Evidence["CloudServiceArtifacts"]
$LAPSData  = $Evidence["LAPS_Status"]
$LogonData = $Evidence["Logon_Sessions_Deep"]
$KerbData  = $Evidence["Kerberoasting_Evidence"]
$DCSData   = $Evidence["DCSync_Detection"]
$WebShell  = $Evidence["IIS_WebShell_Detection"]
$PatchData = $Evidence["PatchLevel"]
$RAMData   = $Evidence["RAMDump"]
$NetCapt   = $Evidence["NetworkPacketCapture"]
$AppXData  = $Evidence["AppX_UWP_Apps"]
$StartData = $Evidence["StartupFolder"]
$RegExec   = $Evidence["RegistryExecutionArtifacts"]
$WSLData   = $Evidence["WSL_HyperV_Virtualization"]
$TPMData   = $Evidence["TPM_SecureBoot_BitLocker"]
$ADData    = $Evidence["ActiveDirectory_DomainArtifacts"]
$AFData    = $Evidence["AntiForensics"]
$IOCMatch  = $Evidence["IOC_Matches"]

Write-Host "[*] Extracting metrics..." -ForegroundColor Cyan

# System metrics
$OSCaption  = try { $SysInfo.System.OSCaption }    catch { "Unknown" }
$OSBuild    = try { $SysInfo.System.BuildNumber }   catch { "Unknown" }
$LastBoot   = try { $SysInfo.System.LastBootTime }  catch { "Unknown" }
$UptimeDays = try { $SysInfo.System.UptimeDays }    catch { "Unknown" }
$DomainName = try { $SysInfo.Domain.DomainName }    catch { "Unknown" }
$DomainRole = try { $SysInfo.Domain.DomainRole }    catch { "Unknown" }
$TotalRAM   = try { "$($SysInfo.System.TotalRAMGB) GB" } catch { "Unknown" }
$CPU        = try { $SysInfo.System.Processor }     catch { "Unknown" }
$TimeZone   = try { $SysInfo.System.TimeZone }      catch { "Unknown" }

# Process
$TotalProcs    = if ($ProcData) { $ProcData.ProcessCount } else { 0 }
$SuspProcs     = if ($ProcData) { @($ProcData.Data | Where-Object { $_.IsSuspicious }).Count } else { 0 }
# Only genuinely-unsigned states count. "Executable Not Found"/"UnknownError"/"Access Denied"
# mean the path was unreadable (protected/system processes, symlinked tools) - not unsigned -
# and previously inflated this to the hundreds on a clean host.
$RealUnsigned = @("NotSigned","HashMismatch","NotTrusted")
$UnsignedProcs = if ($ProcData) { @($ProcData.Data | Where-Object { $_.SignatureStatus -in $RealUnsigned }).Count } else { 0 }

# Network
$TotalConns = if ($NetData) { $NetData.ConnectionCount } else { 0 }
$ExtConns   = if ($NetData) { @($NetData.Data | Where-Object { $_.RemoteAddress -and $_.RemoteAddress -notmatch "^(0\.0\.0\.0|127\.|::1|^$)" -and $_.State -eq "Established" }).Count } else { 0 }
$SuspConns  = if ($NetData) { @($NetData.Data | Where-Object { $_.IsSuspicious }).Count } else { 0 }

# Services
$TotalSvcs    = if ($SvcData) { $SvcData.ServiceCount } else { 0 }
$UnsignedSvcs = if ($SvcData) { @($SvcData.Data | Where-Object { $_.SignatureStatus -in @("NotSigned","HashMismatch","NotTrusted") }).Count } else { 0 }
$SuspSvcs     = if ($SvcData) { @($SvcData.Data | Where-Object { $_.IsSuspicious }).Count } else { 0 }

# Persistence
$RunKeyCount  = if ($RegRun)  { $RegRun.EntryCount }    else { 0 }
$TaskCount    = if ($Tasks)   { $Tasks.TaskCount }       else { 0 }
$SuspTasks    = if ($TasksXML){ $TasksXML.SuspiciousCount } else { 0 }
$WMISubCount  = if ($WMIPers) { $WMIPers.EntryCount }   else { 0 }
$StartupCount = if ($StartData){ $StartData.EntryCount } else { 0 }

# Threat indicators
$COMHijacks   = if ($THData)  { Get-SafeCount $THData.COMHijackCandidates } else { 0 }
$LOLBASHits   = if ($THData)  { Get-SafeCount $THData.LOLBASHits } else { 0 }
$DefExclCount = if ($THData)  { (Get-SafeCount $THData.DefenderExclusions.ExclusionPath) + (Get-SafeCount $THData.DefenderExclusions.ExclusionProcess) } else { 0 }
$UACDisabled  = if ($THData)  { $THData.UACConfig.UACDisabled } else { $false }
# Anti-forensics
$LogClears    = if ($AFData) { Get-SafeCount $AFData.LogClearing } else { 0 }
$AFHigh       = if ($AFData) { [int]$AFData.HighFindings } else { 0 }
$AFMed        = if ($AFData) { [int]$AFData.MediumFindings } else { 0 }
$AFHighOther  = [Math]::Max(0, $AFHigh - $LogClears)   # HighFindings includes log-clear events
# User-supplied IOC matches
$IOCHitCount  = if ($IOCMatch) { [int]$IOCMatch.MatchCount } else { 0 }
$IOCHitInd    = if ($IOCMatch) { [int]$IOCMatch.MatchedIndicators } else { 0 }
$CritPers     = if ($DeepPers){ $DeepPers.CriticalFindings } else { 0 }
$HighPers     = if ($DeepPers){ $DeepPers.HighFindings }     else { 0 }

# Credentials
$WDigest       = try { $CredData.LSASSProtection.WDigestEnabled } catch { $null }
$WDigestRisk   = ($WDigest -eq 1)
$LSASSProtected= try { $CredData.LSASSProtection.RunAsPPL -eq 1 } catch { $false }
$CredMgrCount  = if ($CredData) { Get-SafeCount $CredData.CredentialManager } else { 0 }
$DPAPIKeys     = try { $CredData.DPAPIMasterKeys.Count } catch { 0 }

# USB and hardware
$USBCount     = if ($USBData) { Get-SafeCount $USBData.USBStorHistory } else { 0 }
$UnsignedDrvs = try { $USBData.UnsignedRunningDrivers } catch { 0 }
$WERCount     = if ($USBData) { Get-SafeCount $USBData.WERCrashReports } else { 0 }
$TotalDrivers = try { $USBData.TotalDrivers } catch { 0 }

# Certs
$RogueCerts  = try { $CertData.RogueRootCount } catch { 0 }
$TotalCerts  = try { $CertData.TotalCertificates } catch { 0 }

# Pipes / DLLs
$SuspPipes   = try { $PipeData.SuspiciousCount } catch { 0 }
$TotalPipes  = try { $PipeData.TotalPipes } catch { 0 }
$SuspDLLs    = try { $DLLData.SuspiciousCount } catch { 0 }
$TotalDLLs   = try { $DLLData.TotalEntries } catch { 0 }

# Network / Lateral
$SMBSessions  = if ($LMData) { Get-SafeCount $LMData.SMBSessions } else { 0 }
$OpenShares   = if ($LMData) { Get-SafeCount $LMData.NetworkShares } else { 0 }
$FWRuleCount  = try { $FirewallD.RuleCount } catch { 0 }
$WiFiCount    = try { $Evidence["Network_Advanced"].WiFiCount } catch { 0 }

# Event logs
$SecEvents    = try { $SecLog.EventCount } catch { 0 }
$SuspPS       = try { $PSLog.SuspiciousCount } catch { 0 }
$PSBlocks     = try { $PSLog.ScriptBlockCount } catch { 0 }

# Defender
$DefDetections = try { $DefData.TotalDetections } catch { 0 }
$DefCritical   = try { $DefData.CriticalDetections } catch { 0 }
$DefDisabled   = try { $DefData.DefenderDisabledEvents } catch { 0 }

# Active users
$LocalUsers   = if ($UserData) { Get-SafeCount $UserData.Users } else { 0 }
$AdminUsers   = if ($UserData) { @($UserData.Users | Where-Object { $_.IsAdmin }).Count } else { 0 }

# Logon
$TotalLogons  = try { $LogonData.LogonCount } catch { 0 }
$FailedLogons = try { $LogonData.FailedLogonCount } catch { 0 }
$BruteForce   = try { $LogonData.BruteForceIPCount } catch { 0 }

# Kerberoasting / DCSync
$KerbCandidates = try { $KerbData.KerberoastCandidateCount } catch { 0 }
$DCSyncCands    = try { $DCSData.DCSyncCandidateCount } catch { 0 }
$WebShellCount  = try { $WebShell.SuspectedShellCount } catch { 0 }

# Patch
$PatchCount   = try { $PatchData.HotfixCount } catch { 0 }
$PendingPatch = try { $PatchData.PendingCount } catch { 0 }
$CritPatch    = try { $PatchData.CriticalPending } catch { 0 }

# TPM / Secure Boot
$TPMPresent    = try { $TPMData.TPM.TpmPresent } catch { "Unknown" }
$SecureBootOn  = try { $TPMData.SecureBoot.SecureBootEnabled } catch { "Unknown" }
$BitLockerCount= try { $TPMData.BitLockerVolumes.Count } catch { 0 }

# RAM / Network capture
$RAMSize    = try { "$($RAMData.DumpResult.SizeGB) GB" } catch { "Not collected" }
$RAMHash    = try { $RAMData.DumpResult.SHA256.Substring(0,16) + "..." } catch { "-" }
$CaptureETL = try { "$($NetCapt.ETLSizeMB) MB" } catch { "Not collected" }

Write-Host "[*] Calculating risk score..." -ForegroundColor Cyan

# Two independent scores so hardening posture never inflates the active-threat level:
#   $RiskScore    = Threat score  - active-compromise indicators (drives the headline risk level)
#   $PostureScore = Posture score - hardening/config gaps (reported separately, informational)
$RiskScore    = 0
$PostureScore = 0
$RiskFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-Risk {
    param([string]$Cat,[string]$Finding,[string]$Sev,[int]$Score,[string]$Rec,[string]$MITRE="",
          [ValidateSet("Threat","Posture")][string]$Class="Threat")
    if ($Class -eq "Posture") { $script:PostureScore += $Score } else { $script:RiskScore += $Score }
    $script:RiskFindings.Add([PSCustomObject]@{
        Category=$Cat; Finding=$Finding; Severity=$Sev
        Score=$Score; Recommendation=$Rec; MITRE=$MITRE; Class=$Class
    })
}

# Critical
if ($WDigestRisk)       { Add-Risk "Credential Access" "WDigest enabled - plaintext credentials in LSASS memory" "CRITICAL" 40 "Set HKLM\System\...\WDigest\UseLogonCredential = 0 and reboot" "T1003.001" -Class "Posture" }
if ($CritPers -gt 0)    { Add-Risk "Persistence" "$CritPers critical registry persistence (IFEO/SSP/AppCert DLL)" "CRITICAL" 35 "Investigate and remove unauthorized registry entries immediately" "T1546" }
if ($RogueCerts -gt 0)  { Add-Risk "Defense Evasion" "$RogueCerts unauthorized root certificate(s) installed" "CRITICAL" 30 "Remove from Trusted Root Certification Authorities store" "T1553.004" }
if ($WebShellCount -gt 0){ Add-Risk "Initial Access" "$WebShellCount web shell(s) detected in IIS web root" "CRITICAL" 35 "Immediately quarantine and remove identified web shell files" "T1505.003" }
if ($DCSyncCands -gt 0) { Add-Risk "Credential Access" "$DCSyncCands DCSync candidate(s) detected - unauthorized replication" "CRITICAL" 40 "Revoke replication permissions from non-DC accounts immediately" "T1003.006" }
if ($DefDisabled -gt 0) { Add-Risk "Defense Evasion" "Defender disabled event(s) detected ($DefDisabled events)" "CRITICAL" 35 "Re-enable Defender immediately and investigate disable source" "T1562.001" }
if ($LogClears -gt 0)   { Add-Risk "Defense Evasion" "$LogClears event log clearing event(s) detected (anti-forensics)" "CRITICAL" 35 "Identify who cleared logs and when; treat surrounding timeline as suspect" "T1070.001" }
if ($IOCHitInd -gt 0)   { Add-Risk "Indicator Match" "$IOCHitInd user-supplied IOC(s) matched collected evidence ($IOCHitCount hit(s))" "CRITICAL" 40 "Investigate every artifact containing a matched indicator; treat host as compromised pending review" "T1587" }
if ($BruteForce -gt 0)  { Add-Risk "Credential Access" "$BruteForce source IP(s) performing brute force attacks" "CRITICAL" 30 "Block source IPs and investigate compromised account access" "T1110" }

# High
if ($UnsignedDrvs -gt 0){ Add-Risk "Defense Evasion" "$UnsignedDrvs unsigned kernel driver(s) running" "HIGH" 25 "Investigate unsigned drivers - potential rootkit or malicious driver" "T1014" }
if ($AFHighOther -gt 0) { Add-Risk "Defense Evasion" "$AFHighOther anti-forensic tamper indicator(s) (log channel / Defender / AMSI disabled)" "HIGH" 20 "Review disabled log channels and Defender/AMSI tamper state" "T1562" }
if ($LOLBASHits -gt 0)  { Add-Risk "Execution" "$LOLBASHits LOLBAS binary abuse event(s) in event logs" "HIGH" 20 "Review event logs for context around each LOLBAS execution" "T1218" }
if ($COMHijacks -gt 0)  { Add-Risk "Persistence" "$COMHijacks COM hijacking candidate(s) in HKCU" "HIGH" 20 "Review HKCU\Software\Classes\CLSID for unauthorized entries" "T1546.015" }
if ($UACDisabled)       { Add-Risk "Privilege Escalation" "UAC is disabled - no elevation barrier" "HIGH" 20 "Re-enable UAC via Group Policy or registry" "T1548.002" -Class "Posture" }
if ($SuspPipes -gt 0)   { Add-Risk "Command and Control" "$SuspPipes suspicious named pipe(s) matching C2 patterns" "HIGH" 15 "Investigate named pipes matching known C2 framework patterns (Cobalt Strike etc)" "T1071" }
if ($KerbCandidates -gt 0){ Add-Risk "Credential Access" "$KerbCandidates Kerberoasting RC4 TGS request(s) detected" "HIGH" 20 "Rotate service account passwords and enforce AES-only encryption" "T1558.003" }
if ($DefDetections -gt 0){ Add-Risk "Malware" "$DefDetections historical Defender detection(s) including $DefCritical critical" "HIGH" 20 "Review all detections and verify successful remediation" "T1587" -Class "Posture" }
if ($SuspConns -gt 0)   { Add-Risk "Command and Control" "$SuspConns suspicious network connection(s) to external hosts" "HIGH" 15 "Investigate processes making suspicious outbound connections" "T1071" }
if ($CritPatch -gt 0)   { Add-Risk "Vulnerability" "$CritPatch critical security patch(es) missing" "HIGH" 15 "Apply missing patches immediately - risk of exploitation" "T1190" -Class "Posture" }

# Medium
if (-not $LSASSProtected){ Add-Risk "Credential Access" "LSASS not running as Protected Process (PPL disabled)" "MEDIUM" 10 "Enable RunAsPPL: HKLM\SYSTEM\...\Lsa\RunAsPPL = 1" "T1003.001" -Class "Posture" }
if ($WMISubCount -gt 0)  { Add-Risk "Persistence" "$WMISubCount WMI event subscription(s) active" "MEDIUM" 10 "Review all WMI subscriptions for unauthorized entries" "T1546.003" }
if ($UnsignedProcs -gt 0){ Add-Risk "Execution" "$UnsignedProcs unsigned process executable(s) running" "MEDIUM" 10 "Investigate unsigned processes especially in user-writable paths" "T1204" -Class "Posture" }
if ($DefExclCount -gt 0) { Add-Risk "Defense Evasion" "$DefExclCount Defender exclusion(s) configured" "MEDIUM" 10 "Verify all exclusions are legitimate and authorized" "T1562.001" -Class "Posture" }
if ($AFMed -gt 0)        { Add-Risk "Defense Evasion" "$AFMed anti-forensic configuration indicator(s) (logging/prefetch/USN/audit policy)" "MEDIUM" 8 "Review PowerShell logging, prefetch, USN journal and audit-policy changes" "T1562" }
if ($HighPers -gt 0)     { Add-Risk "Persistence" "$HighPers high-risk deep registry persistence entries" "MEDIUM" 10 "Review SSP, time providers, port monitors, logon scripts" "T1547" }
if ($SuspDLLs -gt 0)     { Add-Risk "Defense Evasion" "$SuspDLLs suspicious DLL(s) loaded from non-standard paths" "MEDIUM" 10 "Investigate DLLs from TEMP/AppData into system processes" "T1574" }
if ($SuspTasks -gt 0)    { Add-Risk "Persistence" "$SuspTasks suspicious scheduled task(s) with encoded/download commands" "MEDIUM" 10 "Review and remove unauthorized scheduled tasks" "T1053.005" }
if ($SuspPS -gt 0)       { Add-Risk "Execution" "$SuspPS suspicious PowerShell script block(s) logged" "MEDIUM" 10 "Review PowerShell event log for malicious command patterns" "T1059.001" }
if ($FailedLogons -gt 5) { Add-Risk "Credential Access" "$FailedLogons failed logon attempts recorded" "MEDIUM" 5 "Investigate source of failed logons - possible credential stuffing" "T1110" -Class "Posture" }

if ($RiskScore -gt 100)    { $RiskScore = 100 }
if ($PostureScore -gt 100) { $PostureScore = 100 }
# Headline risk level is driven ONLY by active-threat indicators, so a well-collected but
# merely-unhardened machine reads LOW/MEDIUM rather than falsely CRITICAL.
$RiskLevel = if ($RiskScore -ge 60) { "CRITICAL" } elseif ($RiskScore -ge 30) { "HIGH" } elseif ($RiskScore -ge 10) { "MEDIUM" } else { "LOW" }
$RiskColor = switch ($RiskLevel) { "CRITICAL"{"#991b1b"} "HIGH"{"#c2410c"} "MEDIUM"{"#b45309"} default{"#15803d"} }
$PostureLevel = if ($PostureScore -ge 60) { "WEAK" } elseif ($PostureScore -ge 30) { "FAIR" } elseif ($PostureScore -ge 10) { "GOOD" } else { "STRONG" }
$PostureColor = switch ($PostureLevel) { "WEAK"{"#991b1b"} "FAIR"{"#b45309"} "GOOD"{"#15803d"} default{"#15803d"} }
$ThreatFindingCount  = @($RiskFindings | Where-Object { $_.Class -ne "Posture" }).Count
$PostureFindingCount = @($RiskFindings | Where-Object { $_.Class -eq "Posture" }).Count

Write-Host "[*] Extracting IOCs..." -ForegroundColor Cyan

$IOCIPs     = [System.Collections.Generic.HashSet[string]]::new()
$IOCDomains = [System.Collections.Generic.HashSet[string]]::new()
$IOCSHA256  = [System.Collections.Generic.HashSet[string]]::new()
$IOCUsers   = [System.Collections.Generic.HashSet[string]]::new()

try { $NetData.Data | Where-Object { $_.RemoteAddress -and $_.RemoteAddress -notmatch "^(0\.0\.0\.0|127\.|::1|^$)" } | ForEach-Object { $IOCIPs.Add($_.RemoteAddress) | Out-Null } } catch {}
try { $ProcData.Data | Where-Object { $_.SHA256 } | ForEach-Object { $IOCSHA256.Add($_.SHA256) | Out-Null } } catch {}
try { $SvcData.Data  | Where-Object { $_.SHA256 } | ForEach-Object { $IOCSHA256.Add($_.SHA256) | Out-Null } } catch {}
try { $DNSData.Data  | Where-Object { $_.EntryName -and $_.EntryName -notmatch "^(\d{1,3}\.){3}\d{1,3}$" } | ForEach-Object { $IOCDomains.Add($_.EntryName) | Out-Null } } catch {}
try { $UserData.Users | Where-Object { $_.Enabled -and $_.UserName -notin @("Administrator","DefaultAccount","Guest","WDAGUtilityAccount") } | ForEach-Object { $IOCUsers.Add($_.UserName) | Out-Null } } catch {}
try { $LogonData.BruteForceIPs | ForEach-Object { $IOCIPs.Add($_.SourceIP) | Out-Null } } catch {}

$IOCData = [PSCustomObject]@{
    CaseNumber="$CaseNum"; Hostname="$Hostname"; GeneratedAt=(Get-Date).ToString("o")
    ExternalIPs=@($IOCIPs); Domains=@($IOCDomains); SHA256Hashes=@($IOCSHA256)
    LocalUsers=@($IOCUsers); TotalIOCs=$IOCIPs.Count+$IOCDomains.Count+$IOCSHA256.Count
}
$IOCData | ConvertTo-Json -Depth 4 | Out-File $IOCJson -Encoding UTF8
$IOCCsvRows = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($IP in $IOCIPs)     { $IOCCsvRows.Add([PSCustomObject]@{Type="IP";Value=$IP;Source="NetworkConnections";Case=$CaseNum}) }
foreach ($D  in $IOCDomains) { $IOCCsvRows.Add([PSCustomObject]@{Type="Domain";Value=$D;Source="DNSCache";Case=$CaseNum}) }
foreach ($H  in $IOCSHA256)  { $IOCCsvRows.Add([PSCustomObject]@{Type="SHA256";Value=$H;Source="Processes/Services";Case=$CaseNum}) }
$IOCCsvRows | Export-Csv $IOCCsv -NoTypeInformation -Encoding UTF8
Write-Log "IOCs: IPs=$($IOCIPs.Count) Domains=$($IOCDomains.Count) Hashes=$($IOCSHA256.Count)"

Write-Host "[*] Generating professional HTML report..." -ForegroundColor Cyan
$GenDate    = Get-Date -Format "dd MMMM yyyy HH:mm:ss"                                  # local time (labelled local)
$GenDateUtc = (Get-Date).ToUniversalTime().ToString("dd MMMM yyyy HH:mm:ss")            # UTC (labelled UTC)

# Real collection-start time: earliest artifact collection timestamp (UTC), not last boot.
$CollectionStart = try {
    $earliest = $Evidence.Values |
        ForEach-Object { try { $_.ChainOfCustody.CollectedAtUTC } catch { $null } } |
        Where-Object { $_ } | Sort-Object | Select-Object -First 1
    if ($earliest) { ([datetime]$earliest).ToString("dd MMMM yyyy HH:mm:ss") + " UTC" } else { "Unknown" }
} catch { "Unknown" }

# Helper: HTML-encode any evidence-derived string before interpolating it into the report,
# so attacker-controlled artifact content (commands, paths, script text) cannot break or
# inject markup. Returns "" for null so empty cells stay empty.
function HtmlEnc { param($s) if ($null -eq $s) { return "" } [System.Net.WebUtility]::HtmlEncode([string]$s) }

# Helper: build badge
function Get-Badge { param([string]$Text,[string]$Color) "<span style='background:$Color;color:white;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:600'>$Text</span>" }
function Get-SevBadge { param([string]$Sev) switch($Sev){"CRITICAL"{Get-Badge "CRITICAL" "#991b1b"}"HIGH"{Get-Badge "HIGH" "#c2410c"}"MEDIUM"{Get-Badge "MEDIUM" "#b45309"}default{Get-Badge "LOW" "#15803d"}} }

# Risk findings rows
$RiskRows = ($RiskFindings | Sort-Object Score -Descending | ForEach-Object {
    $RowBG = switch($_.Severity){"CRITICAL"{"#fff5f5"}"HIGH"{"#fff7ed"}"MEDIUM"{"#fffbeb"}default{"#f0fdf4"}}
    $Border = switch($_.Severity){"CRITICAL"{"#991b1b"}"HIGH"{"#c2410c"}"MEDIUM"{"#b45309"}default{"#15803d"}}
    "<tr style='background:$RowBG;border-left:4px solid $Border'>
        <td style='padding:10px 14px'>$(Get-SevBadge $_.Severity)</td>
        <td style='padding:10px 14px;font-weight:500'>$($_.Category)</td>
        <td style='padding:10px 14px'>$($_.Finding)</td>
        <td style='padding:10px 14px;font-size:11px;color:#6b7280'>$($_.Recommendation)</td>
        <td style='padding:10px 14px;font-size:11px;font-family:monospace;color:#3b82f6'>$($_.MITRE)</td>
    </tr>"
}) -join ""
if (-not $RiskRows) { $RiskRows = "<tr><td colspan='5' style='padding:20px;text-align:center;color:#15803d;font-weight:500'>No significant risk findings detected</td></tr>" }

# Network connections
$NetRows = ""
if ($NetData) {
    $Ext = @($NetData.Data | Where-Object { $_.RemoteAddress -and $_.RemoteAddress -notmatch "^(0\.0\.0\.0|127\.|::1|^$)" -and $_.State -eq "Established" } | Select-Object -First 30)
    $NetRows = ($Ext | ForEach-Object {
        $Susp = if ($_.IsSuspicious) { "background:#fff5f5" } else { "" }
        $RemColor = if ($_.IsSuspicious) { "color:#991b1b;font-weight:600" } else { "" }
        "<tr style='$Susp'>
            <td style='padding:7px 12px;font-size:12px'>$(if($_.IsSuspicious){'<span style=''background:#991b1b;color:white;padding:1px 5px;border-radius:3px;font-size:9px''>SUSP</span> '})$(HtmlEnc $_.ProcessName)</td>
            <td style='padding:7px 12px;font-size:12px'>$($_.PID)</td>
            <td style='padding:7px 12px;font-size:12px;font-family:monospace'>$(HtmlEnc $_.LocalAddress):$($_.LocalPort)</td>
            <td style='padding:7px 12px;font-size:12px;font-family:monospace;$RemColor'>$(HtmlEnc $_.RemoteAddress)</td>
            <td style='padding:7px 12px;font-size:12px'>$($_.RemotePort)</td>
            <td style='padding:7px 12px;font-size:12px'>$($_.State)</td>
            <td style='padding:7px 12px;font-size:10px;color:#6b7280;max-width:200px;overflow:hidden;text-overflow:ellipsis'>$(HtmlEnc $_.ProcessPath)</td>
        </tr>"
    }) -join ""
    if (-not $NetRows) { $NetRows = "<tr><td colspan='7' style='padding:16px;text-align:center;color:#6b7280'>No established external connections found</td></tr>" }
}

# Running processes
$ProcRows = ""
if ($ProcData) {
    $Procs = @($ProcData.Data | Where-Object { $_.IsSuspicious -or ($_.SignatureStatus -in $RealUnsigned) } | Select-Object -First 30)
    if (-not $Procs) { $Procs = @($ProcData.Data | Select-Object -First 20) }
    $ProcRows = ($Procs | ForEach-Object {
        $Susp = if ($_.IsSuspicious) { "background:#fff5f5" } else { "" }
        $SigColor = if ($_.SignatureStatus -notin @("Valid","Unknown","")) { "color:#991b1b" } else { "color:#15803d" }
        "<tr style='$Susp'>
            <td style='padding:7px 12px;font-size:12px'>$(if($_.IsSuspicious){'<span style=''background:#991b1b;color:white;padding:1px 5px;border-radius:3px;font-size:9px''>!</span> '})$(HtmlEnc $_.ProcessName)</td>
            <td style='padding:7px 12px;font-size:12px'>$($_.PID)</td>
            <td style='padding:7px 12px;font-size:12px'>$($_.PPID)</td>
            <td style='padding:7px 12px;font-size:12px;$SigColor'>$(if($_.SignatureStatus){HtmlEnc $_.SignatureStatus}else{'N/A'})</td>
            <td style='padding:7px 12px;font-size:11px;word-break:break-all'>$(HtmlEnc $_.ExecutablePath)</td>
            <td style='padding:7px 12px;font-size:11px;font-family:monospace;color:#6b7280'>$(if($_.SHA256){$_.SHA256.Substring(0,12)+'...'}else{'-'})</td>
            <td style='padding:7px 12px;font-size:11px;color:#6b7280'>$(HtmlEnc $_.Owner)</td>
        </tr>"
    }) -join ""
    if (-not $ProcRows) { $ProcRows = "<tr><td colspan='7' style='padding:16px;text-align:center;color:#6b7280'>No processes loaded</td></tr>" }
}

# Services
$SvcRows = ""
if ($SvcData) {
    $SvcList = @($SvcData.Data | Where-Object { $_.IsSuspicious -or ($_.SignatureStatus -and $_.SignatureStatus -notin @("Valid","Unknown")) } | Select-Object -First 20)
    if (-not $SvcList) { $SvcList = @($SvcData.Data | Where-Object { $_.State -eq "Running" } | Select-Object -First 20) }
    $SvcRows = ($SvcList | ForEach-Object {
        $Susp = if ($_.IsSuspicious) { "background:#fff5f5" } else { "" }
        "<tr style='$Susp'>
            <td style='padding:7px 12px;font-size:12px'>$($_.ServiceName)</td>
            <td style='padding:7px 12px;font-size:12px'>$($_.DisplayName)</td>
            <td style='padding:7px 12px;font-size:12px'>$($_.State)</td>
            <td style='padding:7px 12px;font-size:11px;word-break:break-all'>$(HtmlEnc $_.BinaryPath)</td>
            <td style='padding:7px 12px;font-size:11px'>$(HtmlEnc $_.RunAsAccount)</td>
        </tr>"
    }) -join ""
    if (-not $SvcRows) { $SvcRows = "<tr><td colspan='5' style='padding:16px;text-align:center;color:#6b7280'>No services loaded</td></tr>" }
}

# Users
$UserRows = ""
if ($UserData) {
    $UserRows = ($UserData.Users | ForEach-Object {
        $AdminBadge = if ($_.IsAdmin) { "<span style='background:#c2410c;color:white;padding:1px 5px;border-radius:3px;font-size:9px'>ADMIN</span> " } else { "" }
        $EnabledColor = if (-not $_.Enabled) { "color:#6b7280" } else { "" }
        "<tr style='$EnabledColor'>
            <td style='padding:7px 12px;font-size:12px'>$AdminBadge$(HtmlEnc $_.UserName)</td>
            <td style='padding:7px 12px;font-size:12px'>$(if($_.Enabled){'<span style=''color:#15803d''>Active</span>'}else{'<span style=''color:#6b7280''>Disabled</span>'})</td>
            <td style='padding:7px 12px;font-size:12px'>$($_.LastLogon)</td>
            <td style='padding:7px 12px;font-size:12px'>$($_.PasswordLastSet)</td>
            <td style='padding:7px 12px;font-size:11px;font-family:monospace;color:#6b7280'>$($_.SID)</td>
        </tr>"
    }) -join ""
    if (-not $UserRows) { $UserRows = "<tr><td colspan='5' style='padding:16px;text-align:center;color:#6b7280'>No users found</td></tr>" }
}

# Persistence - run keys
$RunRows = ""
if ($RegRun) {
    $RunRows = ($RegRun.Data | Select-Object -First 20 | ForEach-Object {
        "<tr>
            <td style='padding:7px 12px;font-size:12px;font-weight:500'>$(HtmlEnc $_.ValueName)</td>
            <td style='padding:7px 12px;font-size:11px;word-break:break-all'>$(HtmlEnc $_.Command)</td>
            <td style='padding:7px 12px;font-size:11px;color:#6b7280'>$(HtmlEnc ($_.RegistryPath -replace 'HKEY_LOCAL_MACHINE','HKLM' -replace 'HKEY_CURRENT_USER','HKCU'))</td>
        </tr>"
    }) -join ""
    if (-not $RunRows) { $RunRows = "<tr><td colspan='3' style='padding:16px;text-align:center;color:#6b7280'>No run key entries found</td></tr>" }
}

# Suspicious tasks
$TaskRows = ""
if ($TasksXML) {
    $SuspTaskList = @($TasksXML.AllTasks | Where-Object { $_.IsSuspicious } | Select-Object -First 20)
    if (-not $SuspTaskList) { $SuspTaskList = @($TasksXML.AllTasks | Select-Object -First 15) }
    $TaskRows = ($SuspTaskList | ForEach-Object {
        $Susp = if ($_.IsSuspicious) { "background:#fff5f5" } else { "" }
        "<tr style='$Susp'>
            <td style='padding:7px 12px;font-size:12px'>$(if($_.IsSuspicious){'<span style=''background:#991b1b;color:white;padding:1px 5px;border-radius:3px;font-size:9px''>!</span> '})$(HtmlEnc $_.TaskName)</td>
            <td style='padding:7px 12px;font-size:11px;color:#6b7280'>$(HtmlEnc $_.TaskPath)</td>
            <td style='padding:7px 12px;font-size:12px'>$($_.State)</td>
            <td style='padding:7px 12px;font-size:12px'>$(HtmlEnc $_.RunAs)</td>
            <td style='padding:7px 12px;font-size:11px;color:#c2410c'>$(HtmlEnc $_.SuspiciousReasons)</td>
        </tr>"
    }) -join ""
    if (-not $TaskRows) { $TaskRows = "<tr><td colspan='5' style='padding:16px;text-align:center;color:#6b7280'>No suspicious tasks found</td></tr>" }
}

# Deep persistence
$DeepRows = ""
if ($DeepPers -and $DeepPers.PersistenceFindings) {
    $DeepRows = ($DeepPers.PersistenceFindings | Select-Object -First 20 | ForEach-Object {
        $Color = if ($_.RiskLevel -eq "CRITICAL") { "background:#fff5f5" } elseif ($_.RiskLevel -eq "HIGH") { "background:#fff7ed" } else { "" }
        "<tr style='$Color'>
            <td style='padding:7px 12px;font-size:12px'>$(Get-SevBadge $_.RiskLevel)</td>
            <td style='padding:7px 12px;font-size:12px'>$(HtmlEnc $_.Category)</td>
            <td style='padding:7px 12px;font-size:12px;word-break:break-all'>$(HtmlEnc $_.RegistryKey)</td>
            <td style='padding:7px 12px;font-size:11px;color:#6b7280;word-break:break-all'>$(HtmlEnc $_.Value)</td>
        </tr>"
    }) -join ""
    if (-not $DeepRows) { $DeepRows = "<tr><td colspan='4' style='padding:16px;text-align:center;color:#15803d'>No deep persistence findings</td></tr>" }
}

# Defender detections
$DefRows = ""
if ($DefData -and $DefData.ThreatHistory) {
    $DefRows = ($DefData.ThreatHistory | Select-Object -First 20 | ForEach-Object {
        $Sev = if ($_.Severity -in @("Severe","High")) { "background:#fff5f5" } else { "" }
        "<tr style='$Sev'>
            <td style='padding:7px 12px;font-size:12px;font-weight:500'>$(HtmlEnc $_.ThreatName)</td>
            <td style='padding:7px 12px;font-size:12px'>$(Get-SevBadge $_.Severity)</td>
            <td style='padding:7px 12px;font-size:12px'>$($_.InitialDetectionTime)</td>
            <td style='padding:7px 12px;font-size:12px'>$(if($_.ActionSuccess){'<span style=''color:#15803d''>Remediated</span>'}else{'<span style=''color:#991b1b''>FAILED</span>'})</td>
            <td style='padding:7px 12px;font-size:11px;color:#6b7280'>$(HtmlEnc ($_.Resources -join ','))</td>
        </tr>"
    }) -join ""
    if (-not $DefRows) { $DefRows = "<tr><td colspan='5' style='padding:16px;text-align:center;color:#15803d'>No Defender detections found</td></tr>" }
}

# USB history
$USBRows = ""
if ($USBData -and $USBData.USBStorHistory) {
    $USBRows = ($USBData.USBStorHistory | Select-Object -First 15 | ForEach-Object {
        "<tr>
            <td style='padding:7px 12px;font-size:12px'>$(HtmlEnc $_.FriendlyName)</td>
            <td style='padding:7px 12px;font-size:11px;font-family:monospace'>$(HtmlEnc $_.SerialNumber)</td>
            <td style='padding:7px 12px;font-size:12px'>$(HtmlEnc $_.Manufacturer)</td>
            <td style='padding:7px 12px;font-size:12px'>$(HtmlEnc $_.DeviceType)</td>
            <td style='padding:7px 12px;font-size:12px'>$($_.LastArrival)</td>
        </tr>"
    }) -join ""
    if (-not $USBRows) { $USBRows = "<tr><td colspan='5' style='padding:16px;text-align:center;color:#6b7280'>No USB storage devices found</td></tr>" }
}

# Logon events (suspicious)
$LogonRows = ""
if ($LogonData -and $LogonData.LogonEvents) {
    $SuspLogons = @($LogonData.LogonEvents | Where-Object { $_.IsSuspicious } | Select-Object -First 20)
    if (-not $SuspLogons) { $SuspLogons = @($LogonData.LogonEvents | Select-Object -Last 15) }
    $LogonRows = ($SuspLogons | ForEach-Object {
        $Susp = if ($_.IsSuspicious) { "background:#fff5f5" } else { "" }
        "<tr style='$Susp'>
            <td style='padding:7px 12px;font-size:12px'>$($_.TimeCreated)</td>
            <td style='padding:7px 12px;font-size:12px'>$(HtmlEnc $_.TargetUser)</td>
            <td style='padding:7px 12px;font-size:12px'>$(HtmlEnc $_.LogonTypeName)</td>
            <td style='padding:7px 12px;font-size:12px;font-family:monospace'>$(HtmlEnc $_.SourceIP)</td>
            <td style='padding:7px 12px;font-size:12px'>$(HtmlEnc $_.AuthPackage)</td>
            <td style='padding:7px 12px;font-size:11px;color:#c2410c'>$(HtmlEnc $_.SuspiciousReasons)</td>
        </tr>"
    }) -join ""
    if (-not $LogonRows) { $LogonRows = "<tr><td colspan='6' style='padding:16px;text-align:center;color:#6b7280'>No logon events loaded</td></tr>" }
}

# PS suspicious
$PSRows = ""
if ($PSLog -and $PSLog.ScriptBlockEvents) {
    $SuspPS2 = @($PSLog.ScriptBlockEvents | Where-Object { $_.IsSuspicious } | Select-Object -First 15)
    $PSRows = ($SuspPS2 | ForEach-Object {
        "<tr style='background:#fff5f5'>
            <td style='padding:7px 12px;font-size:12px'>$($_.TimeCreated)</td>
            <td style='padding:7px 12px;font-size:11px;color:#c2410c'>$(HtmlEnc ($_.SuspiciousIndicators -join ', '))</td>
            <td style='padding:7px 12px;font-size:11px;font-family:monospace;word-break:break-all;max-width:400px'>$(if($_.ScriptText){HtmlEnc $_.ScriptText.Substring(0,[Math]::Min(200,$_.ScriptText.Length))})</td>
        </tr>"
    }) -join ""
    if (-not $PSRows) { $PSRows = "<tr><td colspan='3' style='padding:16px;text-align:center;color:#15803d'>No suspicious PowerShell script blocks detected</td></tr>" }
}

# Evidence collection table
$EvidRows = ($Evidence.Keys | Sort-Object | ForEach-Object {
    $D = $Evidence[$_]
    $Cnt = try {
        if     ($D.EventCount)      { $D.EventCount }
        elseif ($D.ProcessCount)    { $D.ProcessCount }
        elseif ($D.ConnectionCount) { $D.ConnectionCount }
        elseif ($D.ServiceCount)    { $D.ServiceCount }
        elseif ($D.TaskCount)       { $D.TaskCount }
        elseif ($D.RuleCount)       { $D.RuleCount }
        elseif ($D.EntryCount)      { $D.EntryCount }
        elseif ($D.TotalEntries)    { $D.TotalEntries }
        elseif ($D.HotfixCount)     { $D.HotfixCount }
        elseif ($D.USBCount)        { $D.USBCount }
        elseif ($D.TotalDetections) { $D.TotalDetections }
        else { "-" }
    } catch { "-" }
    $ColTime = try { $D.ChainOfCustody.CollectedAt.ToString() -replace "T"," " -replace "\.\d+.*","" } catch { "-" }
    $SHA = try { $D.ChainOfCustody.SHA256 } catch { "" }
    "<tr>
        <td style='padding:8px 12px;font-size:12px;font-weight:500'>$_</td>
        <td style='padding:8px 12px;text-align:center'><span style='color:#15803d;font-weight:600'>Collected</span></td>
        <td style='padding:8px 12px;text-align:center;font-size:12px'>$Cnt</td>
        <td style='padding:8px 12px;font-size:11px;color:#6b7280'>$ColTime</td>
    </tr>"
}) -join ""

# -- Collection Coverage ------------------------------------------------------
# Compare the full catalog of artifacts the toolkit can collect against what actually
# landed in this evidence set, so the report shows what was collected vs missed.
Write-Host "[*] Computing collection coverage..." -ForegroundColor Cyan
$ArtifactCatalog = @(
    @{T=@("SystemInformation");             N="System Info";                  C="System"}
    @{T=@("PatchLevel");                    N="Patch Level";                  C="System"}
    @{T=@("TPM_SecureBoot_BitLocker");      N="TPM / Secure Boot / BitLocker";C="System"}
    @{T=@("ARPEntries");                    N="ARP Cache";                    C="Network"}
    @{T=@("DNSCache");                      N="DNS Cache";                    C="Network"}
    @{T=@("NetworkConnections");            N="Network Connections";          C="Network"}
    @{T=@("NetworkPacketCapture");          N="Packet Capture";               C="Network"}
    @{T=@("Network_Advanced");              N="Network (Advanced)";           C="Network"}
    @{T=@("SecurityEventLog");              N="Security Event Log";           C="Event Logs"}
    @{T=@("SystemApplicationEventLog");     N="System / App Event Log";       C="Event Logs"}
    @{T=@("PowerShellEventLog");            N="PowerShell Event Log";         C="Event Logs"}
    @{T=@("RawEventLogExport");             N="Raw EVTX Export";              C="Event Logs"}
    @{T=@("RunningProcesses");              N="Running Processes";            C="Execution"}
    @{T=@("PrefetchFiles");                 N="Prefetch";                     C="Execution"}
    @{T=@("ExecutionHistory");              N="SRUM / Exec History";          C="Execution"}
    @{T=@("PSTranscriptCollection");        N="PowerShell Transcripts";       C="Execution"}
    @{T=@("RegistryRunKeys");               N="Registry Run Keys";            C="Persistence"}
    @{T=@("ScheduledTasks");                N="Scheduled Tasks";              C="Persistence"}
    @{T=@("ScheduledTaskXML");              N="Scheduled Tasks (XML)";        C="Persistence"}
    @{T=@("WindowsServices");               N="Windows Services";             C="Persistence"}
    @{T=@("StartupFolder");                 N="Startup Folder";               C="Persistence"}
    @{T=@("WMIPersistence");                N="WMI Persistence";              C="Persistence"}
    @{T=@("AutorunsPersistenceSummary");    N="Autoruns Summary";             C="Persistence"}
    @{T=@("RegistryExecutionArtifacts");    N="Registry Execution (BAM/UserAssist)"; C="Registry"}
    @{T=@("RegistryHiveExport");            N="Registry Hive Export";         C="Registry"}
    @{T=@("Registry_Deep_Persistence");     N="Deep Registry Persistence";    C="Registry"}
    @{T=@("GPO_Cache_Scripts");             N="GPO Cached Scripts";           C="Registry"}
    @{T=@("CredentialArtifacts");           N="Credential Artifacts";         C="Credentials"}
    @{T=@("LSA_Secrets_Metadata");          N="LSA Secrets (metadata)";       C="Credentials"}
    @{T=@("AV_EDR_Status");                 N="AV / EDR Status";              C="Defense Evasion"}
    @{T=@("Defender_Scan_History");         N="Defender Scan History";        C="Defense Evasion"}
    @{T=@("FirewallRules");                 N="Firewall Rules";               C="Defense Evasion"}
    @{T=@("AntiForensics");                 N="Anti-Forensics";               C="Defense Evasion"}
    @{T=@("LocalUsersAndGroups");           N="Local Users & Groups";         C="Privilege"}
    @{T=@("Logon_Sessions_Deep");           N="Logon Sessions";               C="Privilege"}
    @{T=@("LateralMovement");               N="Lateral Movement";             C="Lateral Movement"}
    @{T=@("ThreatHunting");                 N="Threat Hunting";               C="Threat Hunting"}
    @{T=@("IIS_WebShell_Detection");        N="IIS Web Shells";               C="Threat Hunting"}
    @{T=@("AI_Attack_Detection");           N="AI Attack Detection";          C="Threat Hunting"}
    @{T=@("BrowserArtifacts","WebServerLogs"); N="Browser / Web Server";      C="Browser"}
    @{T=@("NamedPipes");                    N="Named Pipes";                  C="Memory"}
    @{T=@("LoadedDLLs");                    N="Loaded DLLs";                  C="Memory"}
    @{T=@("RAMDump");                       N="RAM Dump";                     C="Memory"}
    @{T=@("FileSystemArtifacts");           N="File System Artifacts";        C="File System"}
    @{T=@("AppX_UWP_Apps");                 N="AppX / UWP Apps";              C="File System"}
    @{T=@("Backup_VSS_Deep");               N="VSS Backups";                  C="File System"}
    @{T=@("MFT_USNJournal_LogFile");        N="MFT / USN / LogFile";          C="File System"}
    @{T=@("USB_Device_Driver_WER");         N="USB / Driver / WER";           C="USB Devices"}
    @{T=@("CertificateStore");              N="Certificate Store";            C="Certificates"}
    @{T=@("Email_Office_Artifacts");        N="Email / Office Artifacts";     C="Email / Office"}
    @{T=@("Office365_Exchange");            N="Office 365 / Exchange";        C="Email / Office"}
    @{T=@("CloudServiceArtifacts");         N="Cloud Artifacts";              C="Cloud"}
    @{T=@("ActiveDirectory_DomainArtifacts");N="AD Domain Artifacts";         C="Active Directory"}
    @{T=@("LAPS_Status");                   N="LAPS Status";                  C="Active Directory"}
    @{T=@("Kerberoasting_Evidence");        N="Kerberoasting";                C="Active Directory"}
    @{T=@("DCSync_Detection");              N="DCSync";                       C="Active Directory"}
    @{T=@("NTDS_Location");                 N="NTDS Location";                C="Active Directory"}
    @{T=@("SQL_Server_Artifacts");          N="SQL Server";                   C="Application"}
    @{T=@("WindowsHello_ModernAuth");       N="Windows Hello / Modern Auth";  C="Accounts"}
    @{T=@("WSL_HyperV_Virtualization");     N="WSL / Hyper-V";                C="Virtualization"}
)
# Determine whether a collected artifact actually contains records (vs ran-but-empty).
# Returns $true if a count field is present and 0, else $false (config/state artifacts with
# no countable list are treated as having content).
function Test-ArtifactEmpty { param($obj)
    if (-not $obj) { return $false }
    $countFields = @('EventCount','ProcessCount','ConnectionCount','ServiceCount','TaskCount','TotalTasks',
        'RuleCount','EntryCount','TotalEntries','HotfixCount','USBCount','TotalDetections','TotalFilesScanned',
        'TotalFindings','LogonCount','RecordCount')
    foreach ($p in $countFields) {
        if (($obj.PSObject.Properties.Name -contains $p) -and ($null -ne $obj.$p)) { return ([int]$obj.$p -eq 0) }
    }
    foreach ($p in @('Data','Findings','PersistenceFindings','Records','Entries')) {
        if (($obj.PSObject.Properties.Name -contains $p) -and ($null -ne $obj.$p)) { return (@($obj.$p).Count -eq 0) }
    }
    return $false   # no countable field - assume this is a state/config artifact with content
}

$CovRows = foreach ($a in $ArtifactCatalog) {
    $present = $null
    foreach ($t in $a.T) { if ($Evidence.Contains($t)) { $present = $Evidence[$t]; break } }
    if (-not $present)                          { $status="Missing";   $empty=$false }
    elseif ("$($present.Status)" -eq "Skipped") { $status="Skipped";   $empty=$false }
    else                                        { $status="Collected"; $empty=(Test-ArtifactEmpty $present) }
    [PSCustomObject]@{ Name=$a.N; Cat=$a.C; Status=$status; Empty=$empty }
}
$CovTotal     = $CovRows.Count
$CovCollected = @($CovRows | Where-Object { $_.Status -eq "Collected" }).Count
$CovWithData  = @($CovRows | Where-Object { $_.Status -eq "Collected" -and -not $_.Empty }).Count
$CovEmpty     = @($CovRows | Where-Object { $_.Status -eq "Collected" -and $_.Empty }).Count
$CovSkipped   = @($CovRows | Where-Object { $_.Status -eq "Skipped" }).Count
$CovMissing   = @($CovRows | Where-Object { $_.Status -eq "Missing" }).Count
$CovPct       = if ($CovTotal) { [math]::Round($CovCollected / $CovTotal * 100) } else { 0 }
$CovPctSkip   = if ($CovTotal) { [math]::Round(($CovCollected + $CovSkipped) / $CovTotal * 100) } else { 0 }
# Completeness bands: >=90% green, >=70% amber, else red.
$CovRingColor = if ($CovPct -ge 90) { "#15803d" } elseif ($CovPct -ge 70) { "#b45309" } else { "#991b1b" }

# Per-category coverage bars (collected = data or empty; both mean the source was captured)
$CovCatRows = ($CovRows | Group-Object Cat | Sort-Object @{E={($_.Group|Where-Object{$_.Status -eq 'Collected'}).Count / $_.Count}} | ForEach-Object {
    $c = @($_.Group | Where-Object { $_.Status -eq "Collected" }).Count
    $pct = [math]::Round($c / $_.Count * 100)
    $barCol = if ($pct -ge 90) { "#15803d" } elseif ($pct -ge 60) { "#b45309" } else { "#991b1b" }
    "<div class='cov-cat'><div class='lbl2'>$(HtmlEnc $_.Name)</div><div class='cov-bar'><i style='width:${pct}%;background:$barCol'></i></div><div class='pct'>$c/$($_.Count) ($pct%)</div></div>"
}) -join ""

# Artifact chips: green = collected with data, outlined slate = collected but empty,
# amber = skipped (needs admin/tool), red = not collected.
$CovChips = ($CovRows | Sort-Object Cat,Name | ForEach-Object {
    if ($_.Status -eq "Collected" -and $_.Empty) {
        $col="#64748b"; $tag="o"; $suffix=" (empty)"; $state="Collected (no records)"
    } elseif ($_.Status -eq "Collected") {
        $col="#15803d"; $tag="+"; $suffix="";         $state="Collected"
    } elseif ($_.Status -eq "Skipped") {
        $col="#b45309"; $tag="~"; $suffix="";         $state="Skipped"
    } else {
        $col="#991b1b"; $tag="x"; $suffix="";         $state="Not collected"
    }
    "<span class='cov-chip' style='border-color:$col;color:$col' title='$(HtmlEnc $_.Cat) - $state'>$tag $(HtmlEnc $_.Name)$suffix</span>"
}) -join ""

$CoverageSection = @"
<!-- S1B: Collection Coverage -->
<div class="section" id="scov">
<div class="section-hdr"><h2>Collection Coverage - What Was Collected vs Missed</h2><span class="badge $(if($CovPct -lt 70){'badge-red'}elseif($CovPct -lt 90){'badge-amber'}else{'badge-green'})">$CovPct% collected</span></div>
<div class="cov-wrap">
  <div class="cov-donut" style="background:conic-gradient($CovRingColor 0% $CovPct%, #b45309 $CovPct% $CovPctSkip%, #e2e8f0 $CovPctSkip% 100%)">
    <div class="cov-donut-inner"><div class="p" style="color:$CovRingColor">$CovPct%</div><div class="s">collected</div></div>
  </div>
  <div class="cov-cats">
    <div style="display:flex;gap:18px;margin-bottom:10px;flex-wrap:wrap">
      <div><div style="font-size:22px;font-weight:800;color:#15803d">$CovWithData</div><div style="font-size:11px;color:#64748b">Collected (with data)</div></div>
      <div><div style="font-size:22px;font-weight:800;color:#64748b">$CovEmpty</div><div style="font-size:11px;color:#64748b">Collected (no records)</div></div>
      <div><div style="font-size:22px;font-weight:800;color:#b45309">$CovSkipped</div><div style="font-size:11px;color:#64748b">Skipped (needs admin/tool)</div></div>
      <div><div style="font-size:22px;font-weight:800;color:#991b1b">$CovMissing</div><div style="font-size:11px;color:#64748b">Not Collected</div></div>
      <div><div style="font-size:22px;font-weight:800;color:#0f2744">$CovTotal</div><div style="font-size:11px;color:#64748b">Total Artifact Types</div></div>
    </div>
    $CovCatRows
    <div class="cov-legend">
      <span><span class="cov-dot" style="background:#15803d"></span>Collected (with data)</span>
      <span><span class="cov-dot" style="background:#64748b"></span>Collected (no records)</span>
      <span><span class="cov-dot" style="background:#b45309"></span>Skipped (needs admin or tool)</span>
      <span><span class="cov-dot" style="background:#991b1b"></span>Not collected</span>
    </div>
  </div>
</div>
<div class="cov-chips">$CovChips</div>
</div>
"@

# HTML
$HTML = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IR Report - $CaseNum - $Hostname</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#f1f5f9;color:#1e293b}
.page-header{background:#0f2744}
.header-top{background:#07192d;padding:10px 40px;display:flex;justify-content:space-between;align-items:center;font-size:11px;color:rgba(255,255,255,.6);letter-spacing:.5px}
.header-main{padding:24px 40px 20px;color:white}
.header-main h1{font-size:24px;font-weight:700;letter-spacing:.3px}
.header-main p{font-size:12px;opacity:.7;margin-top:4px}
.meta-bar{background:#162d4a;padding:12px 40px;display:flex;gap:28px;flex-wrap:wrap}
.meta-item .lbl{font-size:10px;text-transform:uppercase;letter-spacing:.8px;opacity:.55;color:white}
.meta-item .val{font-size:13px;font-weight:500;color:white;margin-top:1px}
.risk-banner{padding:18px 40px;background:$RiskColor;color:white;display:flex;align-items:center;gap:24px;flex-wrap:wrap}
.risk-banner .big{font-size:28px;font-weight:800}
.risk-banner .small{font-size:11px;opacity:.8;text-transform:uppercase;letter-spacing:.5px}
.risk-banner .desc{font-size:13px;opacity:.9;max-width:600px}
.container{max-width:1600px;margin:0 auto;padding:24px 32px}
.section{background:white;border-radius:8px;margin-bottom:20px;box-shadow:0 1px 4px rgba(0,0,0,.07);overflow:hidden}
.section-hdr{background:#f8fafc;border-bottom:2px solid #e2e8f0;padding:13px 18px;display:flex;align-items:center;gap:10px}
.section-hdr h2{font-size:14px;font-weight:700;color:#0f2744}
.badge{background:#0f2744;color:white;font-size:10px;padding:2px 8px;border-radius:10px;font-weight:600}
.badge-red{background:#991b1b}
.badge-amber{background:#b45309}
.badge-green{background:#15803d}
.stat-grid{display:flex;flex-wrap:wrap;gap:12px;padding:18px}
.stat{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:14px 18px;text-align:center;min-width:105px}
.stat .num{font-size:26px;font-weight:800;color:#0f2744}
.stat .lbl{font-size:11px;color:#64748b;margin-top:3px}
.stat.alert{background:#fff5f5;border-color:#fca5a5}
.stat.alert .num{color:#991b1b}
.stat.warn{background:#fffbeb;border-color:#fde68a}
.stat.warn .num{color:#b45309}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:20px}
.grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px}
.info-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;padding:18px}
.info-row{background:#f8fafc;border-left:3px solid #0f2744;border-radius:4px;padding:9px 14px}
.info-row .k{font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.5px}
.info-row .v{font-size:13px;font-weight:500;margin-top:2px}
table{width:100%;border-collapse:collapse}
th{background:#0f2744;color:white;padding:9px 12px;text-align:left;font-size:11px;font-weight:600;letter-spacing:.3px;text-transform:uppercase}
td{border-bottom:1px solid #f1f5f9;vertical-align:top}
tr:hover td{background:#f8fafc!important}
.toc{padding:20px}
.toc a{display:block;color:#0f2744;font-size:13px;padding:4px 0;text-decoration:none;border-bottom:1px solid #f1f5f9}
.toc a:hover{color:#2563eb}
.toc-num{display:inline-block;width:24px;font-size:11px;color:#94a3b8}
.footer{background:#0f2744;color:white;padding:18px 40px;display:flex;justify-content:space-between;font-size:11px;opacity:.9;margin-top:24px}
@media print{body{background:white}.container{padding:0 10px}}
.cov-wrap{display:flex;gap:28px;padding:20px;flex-wrap:wrap;align-items:center}
.cov-donut{width:150px;height:150px;border-radius:50%;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.cov-donut-inner{width:112px;height:112px;border-radius:50%;background:white;display:flex;flex-direction:column;align-items:center;justify-content:center}
.cov-donut-inner .p{font-size:30px;font-weight:800;line-height:1}
.cov-donut-inner .s{font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.5px;margin-top:2px}
.cov-cats{flex:1;min-width:300px}
.cov-cat{display:flex;align-items:center;gap:10px;margin:5px 0;font-size:12px}
.cov-cat .lbl2{width:170px;color:#334155;flex-shrink:0}
.cov-bar{flex:1;height:12px;background:#e2e8f0;border-radius:6px;overflow:hidden}
.cov-bar > i{display:block;height:100%;border-radius:6px}
.cov-cat .pct{width:86px;text-align:right;color:#64748b;flex-shrink:0}
.cov-legend{display:flex;gap:16px;font-size:12px;flex-wrap:wrap;margin-top:12px;color:#475569}
.cov-legend span{display:inline-flex;align-items:center;gap:5px}
.cov-dot{width:10px;height:10px;border-radius:2px;display:inline-block}
.cov-chips{display:flex;flex-wrap:wrap;gap:6px;padding:4px 18px 18px}
.cov-chip{border:1px solid;border-radius:12px;padding:2px 10px;font-size:11px;font-weight:500;background:white;white-space:nowrap}
.rpt-toolbar{position:sticky;top:0;z-index:5;background:#0f2744;padding:10px 16px;border-radius:8px;margin-bottom:16px;display:flex;gap:10px;align-items:center;box-shadow:0 2px 6px rgba(0,0,0,.15)}
.rpt-toolbar input{flex:1;padding:8px 12px;border:none;border-radius:5px;font-size:13px}
.rpt-toolbar .hint{color:rgba(255,255,255,.7);font-size:11px;white-space:nowrap}
th.sortable{cursor:pointer;user-select:none} th.sortable:hover{background:#163758}
th.sortable .arrow{opacity:.5;font-size:9px;margin-left:4px}
.table-note{padding:6px 18px 14px;font-size:11px;color:#6b7280;font-style:italic}
</style>
</head>
<body>

<div class="page-header">
<div class="header-top">
  <span>WINDOWS DFIR TOOLKIT v1.0 - CONFIDENTIAL INCIDENT RESPONSE REPORT</span>
  <span>RESTRICTED - AUTHORIZED INVESTIGATORS ONLY</span>
</div>
<div class="header-main">
  <h1>Incident Response Investigation Report</h1>
  <p>Digital Forensics Evidence Collection and Analysis - Powered by Windows DFIR Toolkit v1.0</p>
</div>
<div class="meta-bar">
  <div class="meta-item"><div class="lbl">Case Number</div><div class="val">$CaseNum</div></div>
  <div class="meta-item"><div class="lbl">Investigator</div><div class="val">$Investigator</div></div>
  <div class="meta-item"><div class="lbl">Host Examined</div><div class="val">$Hostname</div></div>
  <div class="meta-item"><div class="lbl">Operating System</div><div class="val">$OSCaption (Build $OSBuild)</div></div>
  <div class="meta-item"><div class="lbl">Domain</div><div class="val">$DomainName - $DomainRole</div></div>
  <div class="meta-item"><div class="lbl">Last Boot Time</div><div class="val">$LastBoot</div></div>
  <div class="meta-item"><div class="lbl">Uptime</div><div class="val">$UptimeDays days</div></div>
  <div class="meta-item"><div class="lbl">Report Generated</div><div class="val">$GenDateUtc UTC</div></div>
</div>
</div>

<div class="risk-banner">
  <div>
    <div class="small">Threat Level</div>
    <div class="big">$RiskLevel</div>
  </div>
  <div style="width:1px;height:44px;background:rgba(255,255,255,.3)"></div>
  <div>
    <div class="small">Threat Score</div>
    <div class="big">$RiskScore<span style="font-size:16px;font-weight:400">/100</span></div>
    <div class="small" style="opacity:.75">$ThreatFindingCount active-threat finding(s)</div>
  </div>
  <div style="width:1px;height:44px;background:rgba(255,255,255,.3)"></div>
  <div>
    <div class="small">Security Posture</div>
    <div class="big" style="color:$(if($PostureLevel -in @('WEAK','FAIR')){'#fca5a5'}else{'#bbf7d0'})">$PostureLevel <span style="font-size:16px;font-weight:400">($PostureScore/100)</span></div>
    <div class="small" style="opacity:.75">$PostureFindingCount hardening gap(s) - not a compromise signal</div>
  </div>
  <div style="width:1px;height:44px;background:rgba(255,255,255,.3)"></div>
  <div class="desc">Threat Score reflects active-compromise indicators only (log clearing, web shells, DCSync, C2, IOC matches, ...). Security Posture reflects hardening gaps (WDigest, LSASS PPL, patches, ...) and does NOT raise the threat level. Based on $($Evidence.Count) artifact categories. Standards: NIST SP 800-61, ISO 27035, MITRE ATT&amp;CK v15.</div>
</div>

<div class="container">

<div class="rpt-toolbar">
  <input type="text" id="rptSearch" placeholder="Search the whole report (process, IP, user, hash, path, service...)" oninput="rptFilter()">
  <span class="hint">click any column header to sort</span>
</div>

<!-- Table of Contents -->
<div class="section">
<div class="section-hdr"><h2>Table of Contents</h2></div>
<div class="toc">
  <a href="#s1"><span class="toc-num">01</span> Executive Summary and Key Metrics</a>
  <a href="#scov"><span class="toc-num">*</span> Collection Coverage (collected vs missed)</a>
  <a href="#s2"><span class="toc-num">02</span> Risk Findings and Recommendations</a>
  <a href="#s3"><span class="toc-num">03</span> System Information</a>
  <a href="#s4"><span class="toc-num">04</span> Network Connections</a>
  <a href="#s5"><span class="toc-num">05</span> Running Processes</a>
  <a href="#s6"><span class="toc-num">06</span> Windows Services</a>
  <a href="#s7"><span class="toc-num">07</span> User Accounts</a>
  <a href="#s8"><span class="toc-num">08</span> Persistence Mechanisms</a>
  <a href="#s9"><span class="toc-num">09</span> Defender Detections</a>
  <a href="#s10"><span class="toc-num">10</span> Logon Activity</a>
  <a href="#s11"><span class="toc-num">11</span> Suspicious PowerShell Activity</a>
  <a href="#s12"><span class="toc-num">12</span> USB Device History</a>
  <a href="#s13"><span class="toc-num">13</span> IOC Summary</a>
  <a href="#s14"><span class="toc-num">14</span> Evidence Collection Summary</a>
  <a href="#s15"><span class="toc-num">15</span> Chain of Custody</a>
</div>
</div>

<!-- S1: Executive Summary -->
<div class="section" id="s1">
<div class="section-hdr"><h2>01 - Executive Summary - Key Metrics</h2><span class="badge">$($Evidence.Count) artifact types collected</span></div>
<div class="stat-grid">
  <div class="stat $(if($UnsignedProcs -gt 0){'alert'}else{''})"><div class="num">$TotalProcs</div><div class="lbl">Running Processes</div></div>
  <div class="stat $(if($UnsignedProcs -gt 0){'alert'}else{''})"><div class="num">$UnsignedProcs</div><div class="lbl">Unsigned Processes</div></div>
  <div class="stat $(if($SuspProcs -gt 0){'alert'}else{''})"><div class="num">$SuspProcs</div><div class="lbl">Suspicious Processes</div></div>
  <div class="stat $(if($ExtConns -gt 5){'warn'}else{''})"><div class="num">$ExtConns</div><div class="lbl">External Connections</div></div>
  <div class="stat $(if($SuspConns -gt 0){'alert'}else{''})"><div class="num">$SuspConns</div><div class="lbl">Suspicious Connections</div></div>
  <div class="stat"><div class="num">$TotalSvcs</div><div class="lbl">Windows Services</div></div>
  <div class="stat $(if($UnsignedSvcs -gt 0){'alert'}else{''})"><div class="num">$UnsignedSvcs</div><div class="lbl">Unsigned Services</div></div>
  <div class="stat $(if($DefDetections -gt 0){'alert'}else{''})"><div class="num">$DefDetections</div><div class="lbl">AV Detections</div></div>
  <div class="stat $(if($SuspPS -gt 0){'alert'}else{''})"><div class="num">$SuspPS</div><div class="lbl">Suspicious PS Blocks</div></div>
  <div class="stat $(if($FailedLogons -gt 5){'warn'}else{''})"><div class="num">$FailedLogons</div><div class="lbl">Failed Logons</div></div>
  <div class="stat $(if($BruteForce -gt 0){'alert'}else{''})"><div class="num">$BruteForce</div><div class="lbl">Brute Force IPs</div></div>
  <div class="stat $(if($RogueCerts -gt 0){'alert'}else{''})"><div class="num">$RogueCerts</div><div class="lbl">Rogue Root Certs</div></div>
  <div class="stat $(if($WebShellCount -gt 0){'alert'}else{''})"><div class="num">$WebShellCount</div><div class="lbl">Web Shells</div></div>
  <div class="stat $(if($LogClears -gt 0){'alert'}elseif($AFHighOther -gt 0){'warn'}else{''})"><div class="num">$($LogClears + $AFHighOther)</div><div class="lbl">Anti-Forensics</div></div>
  <div class="stat $(if($IOCHitInd -gt 0){'alert'}else{''})"><div class="num">$IOCHitInd</div><div class="lbl">IOC Matches</div></div>
  <div class="stat $(if($KerbCandidates -gt 0){'alert'}else{''})"><div class="num">$KerbCandidates</div><div class="lbl">Kerberoasting</div></div>
  <div class="stat $(if($DCSyncCands -gt 0){'alert'}else{''})"><div class="num">$DCSyncCands</div><div class="lbl">DCSync Candidates</div></div>
  <div class="stat $(if($UnsignedDrvs -gt 0){'alert'}else{''})"><div class="num">$UnsignedDrvs</div><div class="lbl">Unsigned Drivers</div></div>
  <div class="stat $(if($SuspPipes -gt 0){'warn'}else{''})"><div class="num">$SuspPipes</div><div class="lbl">C2 Pipe Patterns</div></div>
  <div class="stat $(if($SuspDLLs -gt 0){'warn'}else{''})"><div class="num">$SuspDLLs</div><div class="lbl">Suspicious DLLs</div></div>
  <div class="stat $(if($CritPatch -gt 0){'alert'}else{''})"><div class="num">$CritPatch</div><div class="lbl">Critical Patches Missing</div></div>
  <div class="stat"><div class="num" style="color:$RiskColor">$RiskScore/100</div><div class="lbl">Threat Score</div></div>
  <div class="stat"><div class="num" style="color:$PostureColor">$PostureScore/100</div><div class="lbl">Posture Gaps</div></div>
</div>
</div>

$CoverageSection

<!-- S2: Risk Findings -->
<div class="section" id="s2">
<div class="section-hdr"><h2>02 - Risk Findings and Recommendations</h2><span class="badge badge-red">$($RiskFindings.Count) findings</span></div>
<table>
  <tr><th style="width:100px">Severity</th><th style="width:160px">Category</th><th>Finding</th><th style="width:300px">Recommendation</th><th style="width:100px">MITRE</th></tr>
  $RiskRows
</table>
</div>

<!-- S3: System Info -->
<div class="section" id="s3">
<div class="section-hdr"><h2>03 - System Information</h2></div>
<div class="info-grid">
  <div class="info-row"><div class="k">Hostname</div><div class="v">$Hostname</div></div>
  <div class="info-row"><div class="k">Operating System</div><div class="v">$OSCaption</div></div>
  <div class="info-row"><div class="k">OS Build</div><div class="v">$OSBuild</div></div>
  <div class="info-row"><div class="k">Processor</div><div class="v">$CPU</div></div>
  <div class="info-row"><div class="k">Total RAM</div><div class="v">$TotalRAM</div></div>
  <div class="info-row"><div class="k">Domain</div><div class="v">$DomainName</div></div>
  <div class="info-row"><div class="k">Domain Role</div><div class="v">$DomainRole</div></div>
  <div class="info-row"><div class="k">Time Zone</div><div class="v">$TimeZone</div></div>
  <div class="info-row"><div class="k">Last Boot Time</div><div class="v">$LastBoot</div></div>
  <div class="info-row"><div class="k">System Uptime</div><div class="v">$UptimeDays days</div></div>
  <div class="info-row"><div class="k">WDigest Status</div><div class="v" style="color:$(if($WDigestRisk){'#991b1b'}else{'#15803d'})">$(if($WDigestRisk){'ENABLED - CRITICAL: Plaintext creds in LSASS'}else{'Disabled (Secure)'})</div></div>
  <div class="info-row"><div class="k">LSASS PPL Protection</div><div class="v" style="color:$(if($LSASSProtected){'#15803d'}else{'#b45309'})">$(if($LSASSProtected){'Enabled (Protected Process)'}else{'Not Protected - credential dump risk'})</div></div>
  <div class="info-row"><div class="k">UAC Status</div><div class="v" style="color:$(if($UACDisabled){'#991b1b'}else{'#15803d'})">$(if($UACDisabled){'DISABLED - HIGH RISK'}else{'Enabled'})</div></div>
  <div class="info-row"><div class="k">TPM Present</div><div class="v">$TPMPresent</div></div>
  <div class="info-row"><div class="k">Secure Boot</div><div class="v">$SecureBootOn</div></div>
  <div class="info-row"><div class="k">BitLocker Volumes</div><div class="v">$BitLockerCount</div></div>
  <div class="info-row"><div class="k">Installed Patches</div><div class="v">$PatchCount ($PendingPatch pending, $CritPatch critical missing)</div></div>
  <div class="info-row"><div class="k">RAM Dump</div><div class="v">$RAMSize</div></div>
  <div class="info-row"><div class="k">Network Capture (ETL)</div><div class="v">$CaptureETL</div></div>
  <div class="info-row"><div class="k">Credential Manager</div><div class="v">$CredMgrCount stored credentials</div></div>
</div>
</div>

<!-- S4: Network -->
<div class="section" id="s4">
<div class="section-hdr"><h2>04 - Active Network Connections (External)</h2><span class="badge $(if($SuspConns -gt 0){'badge-red'}else{''})">$ExtConns external established</span></div>
<table>
  <tr><th>Process</th><th>PID</th><th>Local</th><th>Remote Address</th><th>Port</th><th>State</th><th>Path</th></tr>
  $NetRows
</table>
$(if($ExtConns -gt 30){"<div class='table-note'>Showing first 30 of $ExtConns external connections (search/sort above). Full data in the NetworkConnections JSON.</div>"})
</div>

<!-- S5: Processes -->
<div class="section" id="s5">
<div class="section-hdr"><h2>05 - Running Processes</h2><span class="badge $(if($SuspProcs -gt 0){'badge-red'}else{''})">$TotalProcs total | $SuspProcs suspicious | $UnsignedProcs unsigned</span></div>
<table>
  <tr><th>Process Name</th><th>PID</th><th>PPID</th><th>Signature</th><th>Executable Path</th><th>SHA256</th><th>Owner</th></tr>
  $ProcRows
</table>
$(if($TotalProcs -gt 30){"<div class='table-note'>Showing up to 30 of $TotalProcs processes (suspicious/unsigned prioritized; search/sort above). Full data in the RunningProcesses JSON.</div>"})
</div>

<!-- S6: Services -->
<div class="section" id="s6">
<div class="section-hdr"><h2>06 - Windows Services</h2><span class="badge $(if($SuspSvcs -gt 0){'badge-red'}else{''})">$TotalSvcs total | $SuspSvcs suspicious</span></div>
<table>
  <tr><th>Service Name</th><th>Display Name</th><th>State</th><th>Binary Path</th><th>Run As</th></tr>
  $SvcRows
</table>
$(if($TotalSvcs -gt 20){"<div class='table-note'>Showing up to 20 of $TotalSvcs services (suspicious/unsigned/running prioritized; search/sort above). Full data in the WindowsServices JSON.</div>"})
</div>

<!-- S7: Users -->
<div class="section" id="s7">
<div class="section-hdr"><h2>07 - Local User Accounts</h2><span class="badge">$LocalUsers users | $AdminUsers admins</span></div>
<table>
  <tr><th>Username</th><th>Status</th><th>Last Logon</th><th>Password Last Set</th><th>SID</th></tr>
  $UserRows
</table>
</div>

<!-- S8: Persistence -->
<div class="section" id="s8">
<div class="section-hdr"><h2>08 - Persistence Mechanisms</h2><span class="badge $(if(($CritPers+$HighPers) -gt 0){'badge-red'}else{''})">$RunKeyCount run keys | $TaskCount tasks | $SuspTasks suspicious | $WMISubCount WMI</span></div>
<div style="padding:16px 18px 8px;font-size:12px;font-weight:600;color:#0f2744;border-bottom:1px solid #f1f5f9">Registry Run Keys</div>
<table>
  <tr><th>Value Name</th><th>Command</th><th>Registry Path</th></tr>
  $RunRows
</table>
<div style="padding:16px 18px 8px;font-size:12px;font-weight:600;color:#0f2744;border-bottom:1px solid #f1f5f9;border-top:2px solid #e2e8f0">Scheduled Tasks</div>
<table>
  <tr><th>Task Name</th><th>Task Path</th><th>State</th><th>Run As</th><th>Suspicious Reasons</th></tr>
  $TaskRows
</table>
<div style="padding:16px 18px 8px;font-size:12px;font-weight:600;color:#0f2744;border-bottom:1px solid #f1f5f9;border-top:2px solid #e2e8f0">Deep Registry Persistence</div>
<table>
  <tr><th>Risk</th><th>Category</th><th>Finding</th><th>Detail</th></tr>
  $DeepRows
</table>
</div>

<!-- S9: Defender -->
<div class="section" id="s9">
<div class="section-hdr"><h2>09 - Defender Detections</h2><span class="badge $(if($DefDetections -gt 0){'badge-red'}else{'badge-green'})">$DefDetections total | $DefCritical critical</span></div>
<table>
  <tr><th>Threat Name</th><th>Severity</th><th>Detection Time</th><th>Remediation</th><th>Resources</th></tr>
  $DefRows
</table>
</div>

<!-- S10: Logon -->
<div class="section" id="s10">
<div class="section-hdr"><h2>10 - Logon Activity</h2><span class="badge $(if($BruteForce -gt 0){'badge-red'}else{''})">$TotalLogons logons | $FailedLogons failed | $BruteForce brute force IPs</span></div>
<table>
  <tr><th>Time</th><th>User</th><th>Logon Type</th><th>Source IP</th><th>Auth Package</th><th>Suspicious Reason</th></tr>
  $LogonRows
</table>
</div>

<!-- S11: PowerShell -->
<div class="section" id="s11">
<div class="section-hdr"><h2>11 - Suspicious PowerShell Activity</h2><span class="badge $(if($SuspPS -gt 0){'badge-red'}else{'badge-green'})">$PSBlocks script blocks | $SuspPS suspicious</span></div>
<table>
  <tr><th style="width:160px">Time</th><th style="width:200px">Indicators</th><th>Script Content (truncated)</th></tr>
  $PSRows
</table>
</div>

<!-- S12: USB -->
<div class="section" id="s12">
<div class="section-hdr"><h2>12 - USB Device Connection History</h2><span class="badge $(if($USBCount -gt 3){'badge-amber'}else{''})">$USBCount devices ever connected</span></div>
<table>
  <tr><th>Friendly Name</th><th>Serial Number</th><th>Manufacturer</th><th>Type</th><th>Last Connected</th></tr>
  $USBRows
</table>
</div>

<!-- S13: IOC -->
<div class="section" id="s13">
<div class="section-hdr"><h2>13 - Indicators of Compromise</h2><span class="badge">$($IOCData.TotalIOCs) total IOCs extracted</span></div>
<div class="stat-grid">
  <div class="stat"><div class="num">$($IOCIPs.Count)</div><div class="lbl">External IPs</div></div>
  <div class="stat"><div class="num">$($IOCDomains.Count)</div><div class="lbl">Domains (DNS Cache)</div></div>
  <div class="stat"><div class="num">$($IOCSHA256.Count)</div><div class="lbl">SHA256 Hashes</div></div>
  <div class="stat"><div class="num">$($IOCUsers.Count)</div><div class="lbl">User Accounts</div></div>
</div>
<div style="padding:0 18px 18px">
  <div style="background:#f8fafc;border-radius:6px;padding:14px;font-size:13px;color:#64748b">
    <strong>IOC Export Files:</strong><br>
    JSON: <code>$IOCJson</code><br>
    CSV (SIEM import): <code>$IOCCsv</code><br><br>
    <strong>External IPs:</strong> $(HtmlEnc (($IOCIPs | Select-Object -First 20) -join ", "))$(if($IOCIPs.Count -gt 20){" ... and $($IOCIPs.Count-20) more"})<br>
    <strong>Domains:</strong> $(HtmlEnc (($IOCDomains | Select-Object -First 10) -join ", "))$(if($IOCDomains.Count -gt 10){" ... and $($IOCDomains.Count-10) more"})
  </div>
</div>
</div>

<!-- S14: Evidence Collection -->
<div class="section" id="s14">
<div class="section-hdr"><h2>14 - Evidence Collection Summary</h2><span class="badge badge-green">$($Evidence.Count) artifact types collected</span></div>
<table>
  <tr><th>Artifact Type</th><th style="text-align:center;width:100px">Status</th><th style="text-align:center;width:100px">Records</th><th>Collection Time</th></tr>
  $EvidRows
</table>
</div>

<!-- S15: Chain of Custody -->
<div class="section" id="s15">
<div class="section-hdr"><h2>15 - Chain of Custody Declaration</h2></div>
<div class="info-grid">
  <div class="info-row"><div class="k">Case Number</div><div class="v">$CaseNum</div></div>
  <div class="info-row"><div class="k">Investigator</div><div class="v">$Investigator</div></div>
  <div class="info-row"><div class="k">Host Examined</div><div class="v">$Hostname</div></div>
  <div class="info-row"><div class="k">Collection Started</div><div class="v">$CollectionStart</div></div>
  <div class="info-row"><div class="k">Report Generated</div><div class="v">$GenDateUtc UTC</div></div>
  <div class="info-row"><div class="k">Evidence Location</div><div class="v">$BasePath</div></div>
  <div class="info-row"><div class="k">Toolkit</div><div class="v">Windows DFIR Toolkit v1.0 - MIT License</div></div>
  <div class="info-row"><div class="k">Evidence Integrity</div><div class="v">SHA256 hash per artifact + master manifest</div></div>
  <div class="info-row"><div class="k">Collection Method</div><div class="v">Read-only, forensically sound, RFC 3227 order of volatility</div></div>
  <div class="info-row"><div class="k">Standards Applied</div><div class="v">NIST SP 800-61 Rev2 | NIST SP 800-86 | ISO 27035 | ISO 27037 | RFC 3227 | MITRE ATT&amp;CK v15</div></div>
  <div class="info-row"><div class="k">Artifacts Collected</div><div class="v">$($Evidence.Count) types | $($EvidenceFiles.Count) files | Evidence directory: $BasePath</div></div>
  <div class="info-row"><div class="k">Declaration</div><div class="v">I certify this report was generated using Windows DFIR Toolkit v1.0 on $GenDate. All evidence has been preserved with SHA256 integrity hashes in a read-only, forensically sound manner.</div></div>
</div>
</div>

</div>

<div class="footer">
  <div>Windows DFIR Toolkit v1.0 | Case: $CaseNum | Host: $Hostname | Generated: $GenDate</div>
  <div>CONFIDENTIAL - FOR AUTHORIZED INVESTIGATORS ONLY</div>
</div>
<script>
// Report-wide search + click-to-sort on every data table (no external dependencies).
function rptDataTables(){ return Array.prototype.slice.call(document.querySelectorAll('.container table')); }
function rptHeaderRow(t){ var rows=t.rows; for(var i=0;i<rows.length;i++){ if(rows[i].querySelector('th')) return rows[i]; } return null; }
function rptDataRows(t){ return Array.prototype.slice.call(t.rows).filter(function(r){ return !r.querySelector('th'); }); }
function rptFilter(){
  var s=(document.getElementById('rptSearch').value||'').toLowerCase();
  rptDataTables().forEach(function(t){
    rptDataRows(t).forEach(function(r){
      r.style.display = (!s || r.textContent.toLowerCase().indexOf(s)>=0) ? '' : 'none';
    });
  });
}
(function(){
  rptDataTables().forEach(function(t){
    var hdr=rptHeaderRow(t); if(!hdr) return;
    Array.prototype.forEach.call(hdr.cells, function(th, idx){
      th.className=(th.className?th.className+' ':'')+'sortable';
      th.innerHTML=th.innerHTML+'<span class="arrow">&#8597;</span>';
      var dir=1;
      th.addEventListener('click', function(){
        var rows=rptDataRows(t);
        rows.sort(function(a,b){
          var x=(a.cells[idx]?a.cells[idx].textContent:'').trim();
          var y=(b.cells[idx]?b.cells[idx].textContent:'').trim();
          var nx=parseFloat(x.replace(/[^0-9.\-]/g,'')), ny=parseFloat(y.replace(/[^0-9.\-]/g,''));
          var xnum=/^[\s0-9.,:\-]+$/.test(x)&&x!=='', ynum=/^[\s0-9.,:\-]+$/.test(y)&&y!=='';
          if(xnum&&ynum&&!isNaN(nx)&&!isNaN(ny)) return (nx-ny)*dir;
          return x.localeCompare(y)*dir;
        });
        dir=-dir;
        var parent=rows.length?rows[0].parentNode:t;
        rows.forEach(function(r){ parent.appendChild(r); });
      });
    });
  });
})();
</script>
</body>
</html>
"@

$HTML | Out-File $HTMLFile -Encoding UTF8

# Text summary
$FindingsText = ($RiskFindings | ForEach-Object { "  [$($_.Severity)] $($_.Category): $($_.Finding)`n    MITRE: $($_.MITRE)`n    Action: $($_.Recommendation)" }) -join "`n`n"
if (-not $FindingsText) { $FindingsText = "  No significant findings detected." }

$TextReportContent = @"
================================================================================
    INCIDENT RESPONSE INVESTIGATION REPORT
    Windows DFIR Toolkit v1.0
================================================================================
CASE NUMBER     : $CaseNum
INVESTIGATOR    : $Investigator
HOST EXAMINED   : $Hostname
OPERATING SYSTEM: $OSCaption (Build $OSBuild)
DOMAIN          : $DomainName ($DomainRole)
REPORT GENERATED: $GenDateUtc UTC
STANDARDS       : NIST SP 800-61 Rev2, SANS PICERL, ISO 27035, MITRE ATT&CK v15
================================================================================

THREAT LEVEL    : $RiskLevel (Threat Score: $RiskScore / 100, from $ThreatFindingCount active-threat finding(s))
SECURITY POSTURE: $PostureLevel (Posture Score: $PostureScore / 100, from $PostureFindingCount hardening gap(s) - not a compromise signal)

================================================================================
SYSTEM BASELINE
================================================================================
  Last Boot       : $LastBoot
  Uptime          : $UptimeDays days
  RAM             : $TotalRAM
  WDigest         : $(if($WDigestRisk){'ENABLED - CRITICAL'}else{'Disabled (Secure)'})
  LSASS PPL       : $(if($LSASSProtected){'Protected'}else{'Not Protected'})
  UAC             : $(if($UACDisabled){'DISABLED - HIGH RISK'}else{'Enabled'})
  TPM             : $TPMPresent | Secure Boot: $SecureBootOn
  BitLocker       : $BitLockerCount volumes
  Patches         : $PatchCount installed | $PendingPatch pending | $CritPatch critical missing

================================================================================
KEY FINDINGS ($($RiskFindings.Count) total)
================================================================================
$FindingsText

================================================================================
COLLECTION SUMMARY
================================================================================
  Artifact Types        : $($Evidence.Count)
  Running Processes     : $TotalProcs ($SuspProcs suspicious, $UnsignedProcs unsigned)
  Network Connections   : $TotalConns ($ExtConns external, $SuspConns suspicious)
  Windows Services      : $TotalSvcs ($SuspSvcs suspicious, $UnsignedSvcs unsigned)
  Registry Run Keys     : $RunKeyCount
  Scheduled Tasks       : $TaskCount ($SuspTasks suspicious)
  WMI Subscriptions     : $WMISubCount
  Deep Persistence      : $CritPers critical, $HighPers high
  USB Devices (ever)    : $USBCount
  Unsigned Drivers      : $UnsignedDrvs
  Rogue Root Certs      : $RogueCerts
  Suspicious Pipes      : $SuspPipes
  Suspicious DLLs       : $SuspDLLs
  Defender Detections   : $DefDetections ($DefCritical critical)
  Total Logons          : $TotalLogons ($FailedLogons failed, $BruteForce brute force)
  Suspicious PS Blocks  : $SuspPS of $PSBlocks
  Kerberoasting Cands   : $KerbCandidates
  DCSync Candidates     : $DCSyncCands
  Web Shells Detected   : $WebShellCount
  RAM Dump              : $RAMSize
  Network Capture       : $CaptureETL

================================================================================
COLLECTION COVERAGE
================================================================================
  Coverage          : $CovPct% ($CovCollected of $CovTotal artifact types collected)
  Collected w/ data : $CovWithData
  Collected empty   : $CovEmpty
  Skipped           : $CovSkipped (needs admin or tool)
  Not collected     : $CovMissing
  Missed artifacts  : $(($CovRows | Where-Object { $_.Status -eq 'Missing' } | ForEach-Object { $_.Name }) -join ', ')
  Skipped artifacts : $(($CovRows | Where-Object { $_.Status -eq 'Skipped' } | ForEach-Object { $_.Name }) -join ', ')

================================================================================
IOC SUMMARY
================================================================================
  External IPs          : $($IOCIPs.Count)
  Domains               : $($IOCDomains.Count)
  SHA256 Hashes         : $($IOCSHA256.Count)
  IOC JSON              : $IOCJson
  IOC CSV (SIEM)        : $IOCCsv

================================================================================
CHAIN OF CUSTODY
================================================================================
  I, $Investigator, certify this report was generated using Windows DFIR Toolkit
  v1.0 on $GenDateUtc UTC. All evidence files have been preserved with SHA256
  integrity hashes. Collection was read-only and forensically sound per NIST SP
  800-86 and RFC 3227 guidelines.

  Evidence Directory    : $BasePath
  HTML Report           : $HTMLFile
  Text Summary          : $TextReport
================================================================================
  END OF REPORT | Windows DFIR Toolkit v1.0
================================================================================
"@

$TextReportContent | Out-File $TextReport -Encoding UTF8

Write-Host "[+] Report generation complete" -ForegroundColor Green
Write-Host "[+] HTML Report   : $HTMLFile"  -ForegroundColor Green
Write-Host "[+] Text Summary  : $TextReport" -ForegroundColor Green
Write-Host "[+] IOC JSON      : $IOCJson"    -ForegroundColor Green
Write-Host "[+] IOC CSV       : $IOCCsv"     -ForegroundColor Green
Write-Host "[+] Risk Level    : $RiskLevel (Score: $RiskScore/100)" -ForegroundColor $(if($RiskLevel -eq "CRITICAL"){"Red"}elseif($RiskLevel -eq "HIGH"){"Yellow"}else{"Green"})
Write-Log "Report completed | Risk: $RiskLevel ($RiskScore) | Findings: $($RiskFindings.Count) | IOCs: $($IOCData.TotalIOCs)"
