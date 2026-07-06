#Requires -Version 5.1
<#
.SYNOPSIS
    Windows DFIR Toolkit v1.0 - Master IR Collection Runner

.DESCRIPTION
    Runs all collection scripts in RFC 3227 order of volatility, then
    generates an HTML dashboard, forensic timeline and IR report.

    USAGE:
        cd "C:\path\to\dfir-v3"
        Set-ExecutionPolicy Bypass -Scope Process -Force
        $env:DFIR_CASE = "IR-2026-001"
        $env:DFIR_INV  = "InvestigatorName"
        $env:DFIR_DAYS = "30"
        .\Run_IR_Collection.ps1

        # Phase only
        .\Run_IR_Collection.ps1 -Phase Network
        .\Run_IR_Collection.ps1 -Phase Persistence

        # Skip modules
        .\Run_IR_Collection.ps1 -Skip Browser,SRUM,MFT

.AUTHOR
    DFIR Toolkit

.VERSION
    1.0
#>

param(
    [string]$OutputPath = "",
    [ValidateSet("All","System","Network","Network_Advanced","EventLogs","Memory",
                 "FileSystem","FileSystem_Advanced","Registry","Registry_Advanced",
                 "Credentials","Execution","Persistence","DefenseEvasion","Privilege",
                 "LateralMovement","ThreatHunting","Browser","TPM_SecureBoot",
                 "WindowsHello","ActiveDirectory","CloudArtifacts","USB_Devices",
                 "Certificates","WSL_HyperV","Email_Office","Reporting","RAM_Dump","Patch_Level","AV_EDR","Scheduled_Task_XML","PS_Transcripts","AppX_UWP","LSA_Secrets","GPO_Cache","Backup_VSS","Defender_History","LAPS","Logon_Deep","IIS_WebShell","AI_Attack","Office365","NTDS","SQL_Server","Kerberoasting","DCSync","NetCapture","Anti_Forensics")]
    [string]$Phase = "All",
    [string[]]$Skip = @()
)

$ErrorActionPreference = "Continue"

# Resolve toolkit root
if ($PSScriptRoot -and $PSScriptRoot -ne "") {
    $ToolkitRoot = $PSScriptRoot
} elseif ($MyInvocation.MyCommand.Path) {
    $ToolkitRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
} else {
    $ToolkitRoot = (Get-Location).Path
    Write-Warning "[!] PSScriptRoot empty. Using current directory: $ToolkitRoot"
}

if (-not (Test-Path (Join-Path $ToolkitRoot "Scripts"))) {
    Write-Error "[!] Scripts folder not found at: $ToolkitRoot\Scripts"
    exit 1
}

# Set output path - parameter takes priority over env var, then default
if ($OutputPath -and $OutputPath -ne "") {
    $env:DFIR_OUTPUT = $OutputPath
} elseif (-not $env:DFIR_OUTPUT) {
    $env:DFIR_OUTPUT = "C:\IR_Collection"
}
$OutputBase = $env:DFIR_OUTPUT
New-Item -ItemType Directory -Path $OutputBase -Force | Out-Null

$CaseNumber   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd-HHmmss)" }
$Investigator = if ($env:DFIR_INV)  { $env:DFIR_INV  } else { $env:USERNAME }
$DaysBack     = if ($env:DFIR_DAYS) { $env:DFIR_DAYS } else { "30" }
$BasePath     = $env:DFIR_OUTPUT
$RunTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$MasterLog    = "$OutputBase\MasterRun_${RunTimestamp}.log"
$ManifestFile = "$OutputBase\Evidence_Manifest_${RunTimestamp}.json"

New-Item -ItemType Directory -Path $BasePath -Force | Out-Null

function Write-MasterLog {
    param([string]$M, [string]$L = "INFO")
    $Entry = "$(Get-Date -Format o) [$L] $M"
    Add-Content -Path $MasterLog -Value $Entry
    $FG = switch ($L) { "OK"{"Green"} "WARN"{"Yellow"} "ERROR"{"Red"} "HEAD"{"Magenta"} default{"Cyan"} }
    Write-Host $Entry -ForegroundColor $FG
}

# Banner
Clear-Host
Write-Host "+==============================================================+" -ForegroundColor Magenta
Write-Host "|       WINDOWS DFIR TOOLKIT v1.0 -- IR COLLECTION            |" -ForegroundColor Magenta
Write-Host "|          Advanced Forensic Evidence Collector                |" -ForegroundColor Magenta
Write-Host "+==============================================================+" -ForegroundColor Magenta

Write-MasterLog "=== IR COLLECTION STARTED ===" "HEAD"
Write-MasterLog "Case Number  : $CaseNumber"
Write-MasterLog "Investigator : $Investigator"
Write-MasterLog "Hostname     : $env:COMPUTERNAME"
Write-MasterLog "Phase        : $Phase"
Write-MasterLog "Days Lookback: $DaysBack"
Write-MasterLog "Toolkit Root : $ToolkitRoot"

# NTP check
try {
    $W32 = (w32tm /query /status 2>&1) -join " "
    $NTPSource = if ($W32 -match "Source\s*:\s*(\S+)") { $Matches[1] } else { "Unknown" }
    $NTPOffset = if ($W32 -match "Phase Offset\s*:\s*(\S+)") { $Matches[1] } else { "Unknown" }
} catch { $NTPSource="Error"; $NTPOffset="Error" }
Write-MasterLog "NTP Source: $NTPSource | Offset: $NTPOffset"

# AV Exclusion - collection is READ-ONLY by default. Adding a Defender exclusion modifies
# system state, so it is OPT-IN: set $env:DFIR_ADD_AV_EXCLUSION = "1" to auto-add it. Otherwise
# we only print guidance, leaving the target unchanged (preserves forensic integrity).
try {
    $DefStatus = (Get-MpPreference -ErrorAction SilentlyContinue).DisableRealtimeMonitoring
    if (-not $DefStatus) {
        if ($env:DFIR_ADD_AV_EXCLUSION -eq "1") {
            try {
                Add-MpPreference -ExclusionPath $ToolkitRoot -ErrorAction SilentlyContinue
                Write-MasterLog "Defender exclusion added (opt-in via DFIR_ADD_AV_EXCLUSION) - THIS MODIFIED SYSTEM STATE: $ToolkitRoot" "WARN"
            } catch {
                Write-MasterLog "Cannot add Defender exclusion - add manually if scripts blocked" "WARN"
            }
        } else {
            Write-MasterLog "TIP: if AV blocks scripts, set `$env:DFIR_ADD_AV_EXCLUSION='1' (modifies state) or run: Add-MpPreference -ExclusionPath '$ToolkitRoot'"
        }
    }
} catch {}

# Execution Plan - ordered by RFC 3227 order of volatility: most-volatile first (live memory,
# running process/DLL/pipe state, volatile network state), then progressively less-volatile
# disk and registry artifacts. RAM is captured FIRST, before other scripts perturb memory and
# timestamps. (Live packet capture runs last: it is a forward-in-time window, not a snapshot,
# so volatility ordering does not apply to it.)
$ExecutionPlan = [ordered]@{
    # -- Most volatile: live memory and running state --
    "RAM_Dump"      = @("Memory\RAM_Dump")
    "Memory" = @("Memory\Named_Pipes","Memory\Loaded_DLLs")
    "Execution" = @("Execution\Running_Processes","Execution\Collect_Prefetch","Execution\SRUM_PowerShell_History")
    "Network" = @("Network\ARP_Entries","Network\DNS_Cache","Network\Network_Connections")
    "Network_Advanced" = @("Network_Advanced\Network_Advanced")
    # -- System baseline and event logs --
    "System" = @("System\System_Info")
    "EventLogs" = @("EventLogs\Security_EventLog","EventLogs\System_EventLog","EventLogs\PowerShell_EventLog","EventLogs\EventLogs_Raw_Export")
    # -- Less volatile: disk, registry, persistence and the rest --
    "Persistence" = @("Persistence\Registry_RunKeys","Persistence\Scheduled_Tasks","Persistence\Windows_Services","Persistence\Startup_Folder","Persistence\WMI_Persistence")
    "Registry_Advanced" = @("Registry_Advanced\Registry_Deep_Persistence")
    "DefenseEvasion" = @("DefenseEvasion\Firewall_Rules")
    "Privilege" = @("Privilege\Local_Users_Groups")
    "Credentials" = @("Credentials\Credential_Artifacts")
    "Certificates" = @("Certificates\Certificate_Store")
    "Registry" = @("Registry\Registry_Execution_Artifacts","Registry\Registry_Hive_Export")
    "FileSystem" = @("FileSystem\FileSystem_Artifacts")
    "FileSystem_Advanced" = @("FileSystem_Advanced\MFT_USN_Collection")
    "USB_Devices" = @("USB_Devices\USB_Device_History")
    "LateralMovement" = @("LateralMovement\Lateral_Movement")
    "ThreatHunting" = @("ThreatHunting\ThreatHunting")
    "Browser" = @("Browser\Browser_Artifacts")
    "Email_Office" = @("Email_Office\Email_Office_Artifacts")
    "WSL_HyperV" = @("WSL_HyperV\WSL_HyperV_Artifacts")
    "TPM_SecureBoot" = @("TPM_SecureBoot\TPM_SecureBoot_BitLocker")
    "WindowsHello" = @("WindowsHello\WindowsHello_ModernAuth")
    "ActiveDirectory" = @("ActiveDirectory\ActiveDirectory_Artifacts")
    "CloudArtifacts" = @("CloudArtifacts\Cloud_Artifacts")
    "Patch_Level"   = @("System\Patch_Level")
    "AV_EDR"        = @("DefenseEvasion\AV_EDR_Status")
    "Scheduled_Task_XML" = @("Persistence\Scheduled_Task_XML")
    "PS_Transcripts"= @("Execution\PS_Transcript_Collection")
    "AppX_UWP"      = @("FileSystem\AppX_UWP_Apps")
    "LSA_Secrets"   = @("Credentials\LSA_Secrets_Metadata")
    "GPO_Cache"     = @("Registry\GPO_Cache_Scripts")
    "Backup_VSS"    = @("FileSystem\Backup_VSS_Deep")
    "Defender_History" = @("DefenseEvasion\Defender_Scan_History")
    "LAPS"          = @("ActiveDirectory\LAPS_Status")
    "Logon_Deep"    = @("Privilege\Logon_Sessions_Deep")
    "IIS_WebShell"  = @("ThreatHunting\IIS_WebShell_Detection")
    "AI_Attack"     = @("ThreatHunting\AI_Attack_Detection")
    "Office365"     = @("Email_Office\Office365_Exchange")
    "NTDS"          = @("FileSystem_Advanced\NTDS_Location")
    "SQL_Server"    = @("Application\SQL_Server_Artifacts")
    "Kerberoasting" = @("ActiveDirectory\Kerberoasting_Evidence")
    "DCSync"        = @("ActiveDirectory\DCSync_Detection")
    "Anti_Forensics"= @("DefenseEvasion\Anti_Forensics")
    # -- Forward-in-time live capture: runs last --
    "NetCapture"    = @("Network\Network_Packet_Capture")
}

if ($Phase -ne "All") {
    $PhasePlan = [ordered]@{}
    $PhasePlan[$Phase] = $ExecutionPlan[$Phase]
    $ExecutionPlan = $PhasePlan
}

$Results      = [System.Collections.Generic.List[PSCustomObject]]::new()
$StartTime    = Get-Date
$TotalScripts = 0
foreach ($V in $ExecutionPlan.Values) { $TotalScripts += $V.Count }
$Completed = 0; $Failed = 0; $Skipped = 0

foreach ($PhaseName in $ExecutionPlan.Keys) {
    Write-MasterLog "--- Phase: $PhaseName ---" "HEAD"
    foreach ($ScriptRelPath in $ExecutionPlan[$PhaseName]) {
        $ScriptName = Split-Path $ScriptRelPath -Leaf
        $ScriptFile = Join-Path $ToolkitRoot ("Scripts\" + $ScriptRelPath + ".ps1")

        $ShouldSkip = $false
        foreach ($SkipPattern in $Skip) { if ($ScriptName -match $SkipPattern) { $ShouldSkip = $true; break } }
        if ($ShouldSkip) {
            Write-MasterLog "SKIPPED: $ScriptName" "WARN"
            $Results.Add([PSCustomObject]@{ Phase=$PhaseName; Script=$ScriptName; Status="Skipped"; DurationSec=0; Error=$null })
            $Skipped++; continue
        }

        if (-not (Test-Path $ScriptFile)) {
            Write-MasterLog "NOT FOUND: $ScriptFile" "ERROR"
            $Results.Add([PSCustomObject]@{ Phase=$PhaseName; Script=$ScriptName; Status="NotFound"; DurationSec=0; Error="File not found" })
            $Failed++; continue
        }

        Write-MasterLog "Running: $ScriptName"
        $ScriptStart = Get-Date
        try {
            & $ScriptFile
            $Duration = [math]::Round(((Get-Date) - $ScriptStart).TotalSeconds, 1)
            Write-MasterLog "OK: $ScriptName in ${Duration}s" "OK"
            $Results.Add([PSCustomObject]@{ Phase=$PhaseName; Script=$ScriptName; Status="Success"; DurationSec=$Duration; Error=$null })
            $Completed++
        } catch {
            $Duration = [math]::Round(((Get-Date) - $ScriptStart).TotalSeconds, 1)
            $ErrMsg   = $_.ToString()
            Write-MasterLog "ERROR: $ScriptName -- $ErrMsg" "ERROR"
            $Results.Add([PSCustomObject]@{ Phase=$PhaseName; Script=$ScriptName; Status="Failed"; DurationSec=$Duration; Error=$ErrMsg })
            $Failed++
        }
    }
}

# Correlation
Write-MasterLog "--- Persistence Correlation ---" "HEAD"
$CorrScript = Join-Path $ToolkitRoot "Scripts\Infrastructure\Autoruns_Master_Summary.ps1"
if (Test-Path $CorrScript) {
    try { & $CorrScript; Write-MasterLog "OK: Autoruns_Master_Summary" "OK" }
    catch { Write-MasterLog "ERROR: Autoruns_Master_Summary -- $_" "ERROR" }
}

# Report Generation
if ($Phase -eq "All" -or $Phase -eq "Reporting") {
    Write-MasterLog "--- Generating IR Report ---" "HEAD"
    $ReportScript = Join-Path $ToolkitRoot "Scripts\Reporting\Generate_IR_Report.ps1"
    if (Test-Path $ReportScript) {
        try { & $ReportScript; Write-MasterLog "OK: IR Report generated" "OK" }
        catch { Write-MasterLog "ERROR: Report generation -- $_" "ERROR" }
    }
    Write-MasterLog "--- Building Forensic Timeline ---" "HEAD"
    $TimelineScript = Join-Path $ToolkitRoot "Scripts\Reporting\Timeline_Builder.ps1"
    if (Test-Path $TimelineScript) {
        try { & $TimelineScript; Write-MasterLog "OK: Timeline built" "OK" }
        catch { Write-MasterLog "ERROR: Timeline -- $_" "ERROR" }
    }
    Write-MasterLog "--- IOC Threat Intel Enrichment ---" "HEAD"
    $IOCScript = Join-Path $ToolkitRoot "Scripts\Reporting\IOC_ThreatIntel.ps1"
    if (Test-Path $IOCScript) {
        try { & $IOCScript; Write-MasterLog "OK: IOC enrichment complete" "OK" }
        catch { Write-MasterLog "ERROR: IOC enrichment -- $_" "ERROR" }
    }
}

# Manifest - hash EVERY evidence file recursively (raw EVTX, registry hives, prefetch, $MFT,
# browser SQLite copies, RAM .raw, .pcap, JSON, reports), not just the JSON. This makes the
# master chain-of-custody complete. Excluded: .hash.json sidecars (derivatives), the manifest
# itself, and the master run log (still being written while we hash).
Write-MasterLog "--- Building Evidence Manifest (hashing all raw + structured evidence) ---" "HEAD"
$EvidenceFiles = @(Get-ChildItem $BasePath -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notmatch "\.hash\.json$" -and $_.FullName -ne $ManifestFile -and $_.FullName -ne $MasterLog } |
    ForEach-Object {
        $FH = $null; try { $FH = (Get-FileHash $_.FullName -Algorithm SHA256).Hash } catch {}
        [PSCustomObject]@{
            FileName     = $_.Name
            RelativePath = $_.FullName.Substring($BasePath.TrimEnd('\').Length).TrimStart('\')
            FullPath     = $_.FullName
            SizeBytes    = $_.Length
            Extension    = $_.Extension
            SHA256       = $FH
            LastModified = $_.LastWriteTimeUtc.ToString("o")
        }
    })

$TotalRuntime  = [math]::Round(((Get-Date) - $StartTime).TotalMinutes, 2)
$TotalSizeCalc = 0; foreach ($F in $EvidenceFiles) { $TotalSizeCalc += $F.SizeBytes }

$Manifest = [PSCustomObject]@{
    ManifestVersion  = "1.0"
    ChainOfCustody   = [PSCustomObject]@{
        CaseNumber=$CaseNumber; Investigator=$Investigator; Hostname=$env:COMPUTERNAME
        Domain=$env:USERDOMAIN; CollectionStart=$StartTime.ToString("o"); CollectionEnd=(Get-Date).ToString("o")
        TimeZone=[System.TimeZoneInfo]::Local.Id; NTPSource=$NTPSource; NTPOffset=$NTPOffset; ToolVersion="1.0"
    }
    ExecutionSummary = [PSCustomObject]@{ TotalScripts=$TotalScripts; Completed=$Completed; Failed=$Failed; Skipped=$Skipped; TotalRuntimeMin=$TotalRuntime }
    ScriptResults    = $Results
    EvidenceFiles    = $EvidenceFiles
    TotalFilesCount  = $EvidenceFiles.Count
    TotalSizeBytes   = $TotalSizeCalc
}

$Manifest | ConvertTo-Json -Depth 8 | Out-File -FilePath $ManifestFile -Encoding UTF8
try {
    $MH = Get-FileHash $ManifestFile -Algorithm SHA256
    [PSCustomObject]@{ ManifestFile=$ManifestFile; SHA256=$MH.Hash; Generated=(Get-Date).ToString("o") } |
        ConvertTo-Json | Out-File "$ManifestFile.hash.json" -Encoding UTF8
    Write-MasterLog "Manifest SHA256: $($MH.Hash)"
} catch {}

# Summary
Write-Host ""
Write-Host "+==============================================================+" -ForegroundColor Magenta
Write-Host "|                   COLLECTION COMPLETE                       |" -ForegroundColor Magenta
Write-Host "+==============================================================+" -ForegroundColor Magenta
Write-Host "  Case Number   : $CaseNumber"    -ForegroundColor Cyan
Write-Host "  Investigator  : $Investigator"  -ForegroundColor Cyan
Write-Host "  Runtime       : $TotalRuntime minutes" -ForegroundColor Cyan
Write-Host "  Scripts       : $Completed OK | $Failed Failed | $Skipped Skipped" -ForegroundColor Cyan
Write-Host "  Evidence Files: $($EvidenceFiles.Count)" -ForegroundColor Cyan
Write-Host "  Total Size    : $([math]::Round($TotalSizeCalc/1MB,2)) MB" -ForegroundColor Cyan
Write-Host "  Output Path   : $OutputBase"      -ForegroundColor Green
Write-Host "  Manifest      : $ManifestFile"  -ForegroundColor Green
Write-Host "  Master Log    : $MasterLog"     -ForegroundColor Green
Write-Host ""

if ($Failed -gt 0) {
    Write-Host "  Failed Scripts:" -ForegroundColor Red
    foreach ($R in $Results) {
        if ($R.Status -eq "Failed") { Write-Host "    - $($R.Script): $($R.Error)" -ForegroundColor Red }
    }
}

Write-MasterLog "=== COMPLETE | $Completed OK | $Failed Failed | Runtime: ${TotalRuntime}m | Files: $($EvidenceFiles.Count) ===" "HEAD"
