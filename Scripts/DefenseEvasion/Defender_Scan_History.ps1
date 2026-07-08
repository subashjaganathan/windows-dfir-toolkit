#Requires -Version 5.1
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
$LogFile  = "$BasePath\Defender_History_Execution.log"
$JsonFile = "$BasePath\Defender_History_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "Defender scan history collection started | Case: $CaseNum"

$DaysBack  = if ($env:DFIR_DAYS) { [int]$env:DFIR_DAYS } else { 30 }
$SinceDate = (Get-Date).AddDays(-$DaysBack)

# Full threat detection history
Write-Host "[*] Collecting Defender threat detection history..." -ForegroundColor Cyan
$ThreatHistory = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $Detections = @(Get-MpThreatDetection -ErrorAction SilentlyContinue)
    foreach ($D in $Detections) {
        $ThreatInfo = $null
        try { $ThreatInfo = Get-MpThreat -ThreatID $D.ThreatID -ErrorAction SilentlyContinue } catch {}
        $ThreatHistory.Add([PSCustomObject]@{
            ThreatID             = $D.ThreatID
            ThreatName           = if ($ThreatInfo) { $ThreatInfo.ThreatName } else { "Unknown" }
            SeverityID           = if ($ThreatInfo) { $ThreatInfo.SeverityID } else { $null }
            Severity             = switch ($ThreatInfo.SeverityID) { 1{"Low"} 2{"Moderate"} 4{"High"} 5{"Severe"} default{"Unknown"} }
            CategoryID           = if ($ThreatInfo) { $ThreatInfo.CategoryID } else { $null }
            InitialDetectionTime = if ($D.InitialDetectionTime) { $D.InitialDetectionTime.ToString("o") } else { $null }
            LastDetectionTime    = if ($D.LastThreatStatusChangeTime) { $D.LastThreatStatusChangeTime.ToString("o") } else { $null }
            RemediationTime      = if ($D.RemediationTime) { $D.RemediationTime.ToString("o") } else { $null }
            ActionSuccess        = $D.ActionSuccess
            CurrentStatus        = $D.CurrentThreatExecutionStatus
            Resources            = $D.Resources
            ProcessName          = $D.ProcessName
        })
    }
    Write-Log "Threat detections: $($ThreatHistory.Count)"
} catch { Write-Log "Threat detection query failed: $_" "WARN" }

# Quarantine items
Write-Host "[*] Collecting quarantine items..." -ForegroundColor Cyan
$QuarantineItems = [System.Collections.Generic.List[PSCustomObject]]::new()
$QuarantinePath  = "$env:ProgramData\Microsoft\Windows Defender\Quarantine"
if (Test-Path $QuarantinePath) {
    Get-ChildItem $QuarantinePath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $QuarantineItems.Add([PSCustomObject]@{
            FileName     = $_.Name
            FullPath     = $_.FullName
            SizeBytes    = $_.Length
            CreationTime = $_.CreationTimeUtc.ToString("o")
            LastModified = $_.LastWriteTimeUtc.ToString("o")
        })
    }
}
Write-Log "Quarantine items: $($QuarantineItems.Count)"

# Defender event log - full detection timeline
Write-Host "[*] Collecting Defender event log..." -ForegroundColor Cyan
$DefenderEvents = [System.Collections.Generic.List[PSCustomObject]]::new()
$DefenderEventIDs = @(
    1006,   # Malware detected
    1007,   # Action taken on malware
    1008,   # Action failed
    1009,   # Quarantine restore
    1013,   # History delete
    1014,   # History delete failed
    1116,   # Malware detected
    1117,   # Action taken
    1118,   # Action failed
    1119,   # Critical action taken
    2001,   # Real-time protection change
    2002,   # Real-time protection disabled
    3002,   # Real-time protection error
    5001,   # Real-time protection disabled
    5004,   # Monitoring config changed
    5007,   # Config changed
    5010,   # Antivirus disabled
    5012    # Anti-spyware disabled
)
try {
    $EvFilter = @{
        LogName   = "Microsoft-Windows-Windows Defender/Operational"
        Id        = $DefenderEventIDs
        StartTime = $SinceDate
    }
    $DEvents = @(Get-WinEvent -FilterHashtable $EvFilter -ErrorAction SilentlyContinue)
    foreach ($E in $DEvents) {
        $DefenderEvents.Add([PSCustomObject]@{
            TimeCreated  = $E.TimeCreated.ToString("o")
            EventID      = $E.Id
            Level        = $E.LevelDisplayName
            TaskCategory = $E.TaskDisplayName
            Message      = ($E.Message -split "`r?`n" -join " ").Substring(0,[Math]::Min(300,$E.Message.Length))
        })
    }
    Write-Log "Defender events: $($DefenderEvents.Count)"
} catch { Write-Log "Defender event log query failed: $_" "WARN" }

# Current Defender status and config
Write-Host "[*] Collecting current Defender status..." -ForegroundColor Cyan
$DefenderStatus = [PSCustomObject]@{}
try {
    $Status = Get-MpComputerStatus -ErrorAction SilentlyContinue
    $Prefs  = Get-MpPreference  -ErrorAction SilentlyContinue
    $DefenderStatus = [PSCustomObject]@{
        AntivirusEnabled         = $Status.AntivirusEnabled
        RealTimeProtectionEnabled= $Status.OnAccessProtectionEnabled
        BehaviorMonitorEnabled   = $Status.BehaviorMonitorEnabled
        IsTamperProtected        = $Status.IsTamperProtected
        NISEnabled               = $Status.NISEnabled
        AMServiceEnabled         = $Status.AMServiceEnabled
        AntivirusSigVersion      = $Status.AntivirusSignatureVersion
        AntivirusSigAge          = $Status.AntivirusSignatureAge
        LastFullScanEnd          = if ($Status.FullScanEndTime) { $Status.FullScanEndTime.ToString("o") } else { $null }
        LastQuickScanEnd         = if ($Status.QuickScanEndTime) { $Status.QuickScanEndTime.ToString("o") } else { $null }
        ExclusionPaths           = $Prefs.ExclusionPath
        ExclusionProcesses       = $Prefs.ExclusionProcess
        ExclusionExtensions      = $Prefs.ExclusionExtension
        DisableRealtimeMonitoring= $Prefs.DisableRealtimeMonitoring
        SignatureOutdated         = ($Status.AntivirusSignatureAge -gt 7)
    }
} catch { Write-Log "Defender status failed: $_" "WARN" }

# Detection stats summary
$CriticalDetections = @($ThreatHistory | Where-Object { $_.Severity -eq "Severe" -or $_.Severity -eq "High" }).Count
$FailedActions      = @($ThreatHistory | Where-Object { $_.ActionSuccess -eq $false }).Count
$DisabledEvents     = @($DefenderEvents | Where-Object { $_.EventID -in @(5001,5004,5010,5012,2002) }).Count

Write-Log "Detections: $($ThreatHistory.Count) | Critical: $CriticalDetections | Failed: $FailedActions | Disabled events: $DisabledEvents"

$Evidence = [PSCustomObject]@{
    ChainOfCustody       = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=([DateTime]::UtcNow).ToString("o"); ToolVersion=$Global:DFIR_ToolVersion }
    ArtifactType         = "Defender_Scan_History"
    TotalDetections      = $ThreatHistory.Count
    CriticalDetections   = $CriticalDetections
    FailedRemediations   = $FailedActions
    DefenderDisabledEvents = $DisabledEvents
    QuarantineFileCount  = $QuarantineItems.Count
    CurrentStatus        = $DefenderStatus
    ThreatHistory        = $ThreatHistory
    QuarantineItems      = $QuarantineItems
    DefenderEvents       = $DefenderEvents
}

$Evidence | ConvertTo-Json -Depth 7 | Out-File $JsonFile -Encoding UTF8
$Hash = Get-FileHash $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=([DateTime]::UtcNow).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] Defender history complete | Detections: $($ThreatHistory.Count) | Critical: $CriticalDetections | Failed: $FailedActions | Disabled Events: $DisabledEvents" -ForegroundColor Green
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed"
