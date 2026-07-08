#Requires -Version 5.1
<#
.SYNOPSIS
    Detects anti-forensic and log/telemetry tampering activity.

.DESCRIPTION
    Consolidates the indicators an attacker leaves when trying to blind defenders and
    destroy evidence: event-log clearing, disabled log channels, disabled PowerShell
    logging, Defender/AMSI tampering, USN journal deletion, prefetch disablement, and
    audit-policy changes. Tuned to avoid false positives on legitimate configurations
    (third-party AV, Server SKUs, default-off logging).

.IR_PHASE
    Defense Evasion / Anti-Forensics

.MITRE_ATTCK
    T1070.001 - Indicator Removal: Clear Windows Event Logs
    T1070.002 - Indicator Removal: Clear Linux/Mac Logs (n/a)
    T1562.001 - Impair Defenses: Disable or Modify Tools
    T1562.002 - Impair Defenses: Disable Windows Event Logging
    T1562.006 - Impair Defenses: Indicator Blocking
    T1070.004 - Indicator Removal: File Deletion (USN/VSS)

.FORENSIC_SAFETY
    Read-only, forensic-safe

.AUTHOR
    DFIR Toolkit

.VERSION
    1.0
#>

Set-StrictMode -Off
$ErrorActionPreference = "Continue"


# --- Shared toolkit module: single source of truth for version + base paths ---
$__DFIRMod = Join-Path $PSScriptRoot '..\Infrastructure\DFIR_Common.psm1'
if (Test-Path $__DFIRMod) { Import-Module $__DFIRMod -Force -ErrorAction SilentlyContinue }
if (-not $Global:DFIR_ToolVersion) { $Global:DFIR_ToolVersion = '1.0' }
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
$LogFile  = "$BasePath\Anti_Forensics_Execution.log"
$JsonFile = "$BasePath\Anti_Forensics_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "Anti-forensics collection started | Case: $CaseNum | Admin: $IsAdmin"

$DaysBack  = if ($env:DFIR_DAYS) { [int]$env:DFIR_DAYS } else { 30 }
$SinceDate = (Get-Date).AddDays(-$DaysBack)

$Findings = [System.Collections.Generic.List[PSCustomObject]]::new()
function Add-Finding { param($Category,$Severity,$Title,$Detail,$MITRE="",$Time=$null)
    $Findings.Add([PSCustomObject]@{ Category=$Category; Severity=$Severity; Title=$Title; Detail=$Detail; MITRE=$MITRE; TimeCreated=$Time })
}
function Get-RegVal { param([string]$Path,[string]$Name)
    try { $k=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($Path); if ($k){ return $k.GetValue($Name,$null) } } catch {}
    $null
}

# Is a non-Defender AV registered? (used to avoid flagging Defender realtime-off as tampering)
$ThirdPartyAV = $false
try {
    $avs = Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
    $ThirdPartyAV = [bool]($avs | Where-Object { $_.displayName -and $_.displayName -notmatch '(?i)Windows Defender|Microsoft Defender' })
} catch {}

$IsServerOS = $false
try { $IsServerOS = ((Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).ProductType -ne 1) } catch {}

# -- (1) Event log clearing ----------------------------------------------------
Write-Host "[*] Checking for cleared event logs..." -ForegroundColor Cyan
$LogClearing = [System.Collections.Generic.List[PSCustomObject]]::new()
# Security 1102 = audit log cleared; System 104 = an event log was cleared.
foreach ($q in @(@{Log='Security';Id=1102}, @{Log='System';Id=104})) {
    try {
        Get-WinEvent -FilterHashtable @{ LogName=$q.Log; Id=$q.Id; StartTime=$SinceDate } -ErrorAction SilentlyContinue | ForEach-Object {
            $who = $null
            try { $who = ($_.Properties[1].Value.ToString() + '\' + $_.Properties[0].Value.ToString()) } catch {}
            $rec = [PSCustomObject]@{ Log=$q.Log; EventID=$q.Id; TimeCreated=$_.TimeCreated.ToString("o"); ClearedBy=$who }
            $LogClearing.Add($rec)
            Add-Finding "LogClearing" "HIGH" "$($q.Log) event log cleared (Event $($q.Id))" "Cleared by: $who" "T1070.001" $_.TimeCreated.ToString("o")
        }
    } catch { Write-Log "1102/104 query on $($q.Log) failed (needs admin?): $_" "WARN" }
}
Write-Log "Log-clearing events: $($LogClearing.Count)"

# -- (2) Disabled / crippled log channels --------------------------------------
Write-Host "[*] Checking event log channel state..." -ForegroundColor Cyan
$ChannelState = [System.Collections.Generic.List[PSCustomObject]]::new()
# Channels that are ENABLED BY DEFAULT on Windows 10/11 - turning them off blinds detection.
# (TaskScheduler/Operational and many other Operational logs are OFF by default, so flagging
# them would be a false positive; they are deliberately excluded.)
$ImportantChannels = @("Security","System","Windows PowerShell",
    "Microsoft-Windows-PowerShell/Operational","Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-Sysmon/Operational")
foreach ($ch in $ImportantChannels) {
    try {
        $li = Get-WinEvent -ListLog $ch -ErrorAction SilentlyContinue
        if (-not $li) { continue }   # channel not present (e.g. Sysmon not installed) is not tampering
        $ChannelState.Add([PSCustomObject]@{ Channel=$ch; Enabled=$li.IsEnabled; MaxSizeMB=[math]::Round($li.MaximumSizeInBytes/1MB,1); RecordCount=$li.RecordCount })
        if (-not $li.IsEnabled) {
            Add-Finding "LogChannelDisabled" "HIGH" "Event log channel disabled: $ch" "A normally-enabled log channel is turned off - detection blind spot" "T1562.002"
        }
    } catch {}
}

# -- (3) PowerShell logging explicitly disabled --------------------------------
# Only flag values EXPLICITLY set to 0 (someone turned it off). Absence = default, not tampering.
Write-Host "[*] Checking PowerShell logging policy..." -ForegroundColor Cyan
$PSLogging = [ordered]@{}
foreach ($p in @(
    @{K='SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; V='EnableScriptBlockLogging'; N='ScriptBlockLogging'},
    @{K='SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging';      V='EnableModuleLogging';      N='ModuleLogging'},
    @{K='SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription';      V='EnableTranscription';      N='Transcription'})) {
    $val = Get-RegVal $p.K $p.V
    $PSLogging[$p.N] = if ($null -eq $val) { "NotConfigured" } elseif ($val -eq 1) { "Enabled" } else { "Disabled" }
    if ($val -eq 0) {
        Add-Finding "PSLoggingDisabled" "MEDIUM" "PowerShell $($p.N) explicitly disabled by policy" "$($p.K)\$($p.V) = 0" "T1562.006"
    }
}

# -- (4) Defender / AMSI tampering ---------------------------------------------
Write-Host "[*] Checking Defender / AMSI tamper state..." -ForegroundColor Cyan
$DefenderState = [ordered]@{ ThirdPartyAVPresent = $ThirdPartyAV }
try {
    $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
    $pr = Get-MpPreference -ErrorAction SilentlyContinue
    if ($mp) {
        $DefenderState.RealTimeProtection = $mp.RealTimeProtectionEnabled
        $DefenderState.TamperProtection   = $mp.IsTamperProtected
        $DefenderState.AntivirusEnabled   = $mp.AntivirusEnabled
        # Realtime off is expected when a third-party AV owns protection; only notable otherwise.
        if (-not $mp.RealTimeProtectionEnabled -and -not $ThirdPartyAV) {
            Add-Finding "DefenderTamper" "HIGH" "Defender real-time protection disabled" "No third-party AV registered - protection is off" "T1562.001"
        }
        if ($mp.PSObject.Properties.Name -contains 'IsTamperProtected' -and -not $mp.IsTamperProtected -and -not $ThirdPartyAV) {
            Add-Finding "DefenderTamper" "MEDIUM" "Defender Tamper Protection disabled" "Tamper Protection is off" "T1562.001"
        }
    }
    if ($pr) {
        foreach ($tog in @('DisableRealtimeMonitoring','DisableBehaviorMonitoring','DisableScriptScanning','DisableIOAVProtection','DisableBlockAtFirstSeen')) {
            if ($pr.$tog -eq $true -and -not $ThirdPartyAV) {
                Add-Finding "DefenderTamper" "MEDIUM" "Defender setting disabled: $tog" "Get-MpPreference.$tog = True" "T1562.001"
            }
            $DefenderState[$tog] = $pr.$tog
        }
    }
} catch { Write-Log "Defender status query failed: $_" "WARN" }

# AMSI providers - an empty providers key means AMSI has no scanner registered.
$AmsiProviders = @()
try {
    $ap = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\AMSI\Providers')
    if ($ap) {
        $AmsiProviders = @($ap.GetSubKeyNames())
        if ($AmsiProviders.Count -eq 0) {
            Add-Finding "AmsiTamper" "HIGH" "No AMSI providers registered" "AMSI has no scan provider - script scanning is blinded" "T1562.001"
        }
    }
} catch {}

# -- (5) USN journal state -----------------------------------------------------
Write-Host "[*] Checking USN change journal state..." -ForegroundColor Cyan
$UsnJournal = [ordered]@{}
try {
    $usn = (fsutil usn queryjournal C: 2>&1) -join "`n"
    if ($usn -match "(?i)not active|error|cannot") {
        $UsnJournal.Status = "NotActive"
        Add-Finding "UsnJournalDeleted" "MEDIUM" "USN change journal not active on C:" "A deleted/reset journal can indicate anti-forensic file-activity wiping" "T1070.004"
    } else {
        $UsnJournal.Status = "Active"
        if ($usn -match "Maximum Size\s*:\s*(0x[0-9a-fA-F]+)") { $UsnJournal.MaxSize = $Matches[1] }
        if ($usn -match "Next Usn\s*:\s*(0x[0-9a-fA-F]+)")     { $UsnJournal.NextUsn = $Matches[1] }
    }
} catch { $UsnJournal.Status = "Unknown"; Write-Log "fsutil usn query failed (needs admin?): $_" "WARN" }

# -- (6) Prefetch disabled -----------------------------------------------------
Write-Host "[*] Checking prefetch configuration..." -ForegroundColor Cyan
$Pf = Get-RegVal 'SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' 'EnablePrefetcher'
$PrefetchState = [ordered]@{ EnablePrefetcher = $Pf; ServerOS = $IsServerOS }
# On client SKUs prefetch is on by default; disabling it removes execution evidence. On Server
# it is legitimately often disabled, so only flag on client OS.
if ($Pf -eq 0 -and -not $IsServerOS) {
    Add-Finding "PrefetchDisabled" "MEDIUM" "Prefetch is disabled" "EnablePrefetcher = 0 on a client OS removes program-execution evidence" "T1562.001"
}

# -- (7) Audit policy changes --------------------------------------------------
Write-Host "[*] Checking for audit policy changes..." -ForegroundColor Cyan
$AuditChanges = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    # Security 4719 = system audit policy was changed. Legitimate via GPO, so MEDIUM + correlate.
    Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4719; StartTime=$SinceDate } -ErrorAction SilentlyContinue |
        Select-Object -First 50 | ForEach-Object {
            $AuditChanges.Add([PSCustomObject]@{ TimeCreated=$_.TimeCreated.ToString("o"); Message=($_.Message -split "`r?`n" | Select-Object -First 1) })
        }
    if ($AuditChanges.Count -gt 0) {
        Add-Finding "AuditPolicyChanged" "MEDIUM" "$($AuditChanges.Count) audit-policy change event(s) (4719)" "Correlate with authorized GPO changes; unexpected changes may indicate log evasion" "T1562.002"
    }
} catch { Write-Log "4719 query failed (needs admin?): $_" "WARN" }

$CriticalCount = @($Findings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
$HighCount     = @($Findings | Where-Object { $_.Severity -eq "HIGH" }).Count
$MediumCount   = @($Findings | Where-Object { $_.Severity -eq "MEDIUM" }).Count
Write-Log "Anti-forensics findings: HIGH=$HighCount MEDIUM=$MediumCount | LogClears=$($LogClearing.Count)"

$Evidence = [PSCustomObject]@{
    ChainOfCustody   = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=([DateTime]::UtcNow).ToString("o"); ToolVersion=$Global:DFIR_ToolVersion; IsAdmin=$IsAdmin }
    ArtifactType     = "AntiForensics"
    CriticalFindings = $CriticalCount
    HighFindings     = $HighCount
    MediumFindings   = $MediumCount
    Findings         = $Findings
    LogClearing      = $LogClearing
    ChannelState     = $ChannelState
    PowerShellLogging= [PSCustomObject]$PSLogging
    DefenderState    = [PSCustomObject]$DefenderState
    AmsiProviders    = $AmsiProviders
    UsnJournal       = [PSCustomObject]$UsnJournal
    PrefetchState    = [PSCustomObject]$PrefetchState
    AuditPolicyChanges = $AuditChanges
    Note             = if (-not $IsAdmin) { "Run elevated: Security-log indicators (1102, 4719) and USN journal require Administrator." } else { $null }
}

$Evidence | ConvertTo-Json -Depth 6 | Out-File -FilePath $JsonFile -Encoding UTF8
$Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=([DateTime]::UtcNow).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] Anti-forensics collected | HIGH: $HighCount | MEDIUM: $MediumCount | Log clears: $($LogClearing.Count)" -ForegroundColor Green
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed"
