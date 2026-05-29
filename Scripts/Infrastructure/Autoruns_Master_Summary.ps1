<#
.SYNOPSIS
    Generates a unified Autoruns-style persistence summary.

.DESCRIPTION
    Aggregates persistence artifacts collected from multiple DFIR
    scripts (Run Keys, Services, Scheduled Tasks, Startup Folder,
    WMI Subscriptions) into a single, structured persistence view.
    Run this AFTER all individual persistence scripts have completed.

.IR_PHASE
    Persistence / Triage / Investigation

.MITRE_ATTCK
    T1547 - Boot or Logon Autostart Execution
    T1546 - Event Triggered Execution
    T1053 - Scheduled Task
    T1543 - Windows Service

.FORENSIC_SAFETY
    Read-only, offline, forensic-safe

.PREREQUISITE
    Run the following scripts first:
      - Registry_RunKeys.ps1
      - Scheduled_Tasks.ps1
      - Windows_Services.ps1
      - Startup_Folder.ps1
      - WMI_Persistence.ps1

.OUTPUT
    JSON persistence summary + SHA256 hash

.AUTHOR
    DFIR Toolkit

.VERSION
    1.1
#>

Set-StrictMode -Off
$ErrorActionPreference = "Continue"

# =========================
# Environment / Paths
# =========================
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
$LogFile   = "$BasePath\Autoruns_Summary_Execution.log"   # FIX: was missing log file

New-Item -ItemType Directory -Path $BasePath -Force | Out-Null

function Write-Log {
    param([string]$Message)
    Add-Content -Path $LogFile -Value "$(Get-Date -Format o) :: $Message"
}

Write-Log "Autoruns persistence summary started"

$OutputFile = "$BasePath\Autoruns_Persistence_Summary_${Hostname}_${Timestamp}.json"
$HashFile   = "$OutputFile.hash.json"

Write-Host "[*] Building Autoruns-style persistence summary..." -ForegroundColor Cyan

# =========================
# Load JSON Artifacts
# FIX: Load-Artifact was using unapproved verb; renamed to Import-Artifact
# FIX: Added null guard so missing files don't silently produce no data
# =========================
function Import-Artifact {
    param([string]$Pattern)
    $Files = Get-ChildItem -Path $BasePath -Filter $Pattern -ErrorAction SilentlyContinue
    if (-not $Files) {
        Write-Warning "[!] No artifact file found matching: $Pattern"
        Write-Log "WARNING: No file matched pattern '$Pattern'"
        return $null
    }
    # Take the most recent file if multiple exist
    $Latest = $Files | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    try {
        $Obj = Get-Content $Latest.FullName -Raw | ConvertFrom-Json
        Write-Log "Loaded artifact: $($Latest.Name)"
        return $Obj
    } catch {
        Write-Warning "[!] Failed to parse $($Latest.Name): $_"
        Write-Log "ERROR parsing $($Latest.Name): $_"
        return $null
    }
}

$RunKeyArtifact  = Import-Artifact "Registry_RunKeys_*.json"
$TaskArtifact    = Import-Artifact "Scheduled_Tasks_*.json"
$ServiceArtifact = Import-Artifact "Windows_Services_*.json"
$StartupArtifact = Import-Artifact "Startup_Folder_*.json"
$WmiArtifact     = Import-Artifact "WMI_Persistence_*.json"

# =========================
# Normalize Persistence Data
# FIX: @() guards prevent errors when .Data property is null
# FIX: Added SourceFile and Enabled fields for richer triage
# =========================
$Persistence = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($Item in @($RunKeyArtifact.Data)) {
    if ($null -eq $Item) { continue }
    $Persistence.Add([PSCustomObject]@{
        Source    = "RegistryRunKey"
        Name      = $Item.ValueName
        Location  = $Item.RegistryPath
        Command   = $Item.Command
        RunAsUser = $null
        Enabled   = $true
    })
}

foreach ($Item in @($TaskArtifact.Data)) {
    if ($null -eq $Item) { continue }
    $Persistence.Add([PSCustomObject]@{
        Source    = "ScheduledTask"
        Name      = $Item.TaskName
        Location  = $Item.TaskPath
        Command   = "$($Item.Command) $($Item.Arguments)".Trim()
        RunAsUser = $Item.RunAsUser
        Enabled   = ($Item.State -eq "Ready" -or $Item.State -eq "Running")
    })
}

foreach ($Item in @($ServiceArtifact.Data)) {
    if ($null -eq $Item) { continue }
    $Persistence.Add([PSCustomObject]@{
        Source    = "Service"
        Name      = $Item.ServiceName
        Location  = $Item.BinaryPath
        Command   = $Item.BinaryPath
        RunAsUser = $Item.RunAsAccount
        Enabled   = ($Item.StartMode -ne "Disabled")
    })
}

foreach ($Item in @($StartupArtifact.Data)) {
    if ($null -eq $Item) { continue }
    $Persistence.Add([PSCustomObject]@{
        Source    = "StartupFolder"
        Name      = $Item.FileName
        Location  = $Item.StartupPath
        Command   = if ($Item.TargetPath) { $Item.TargetPath } else { $Item.FullPath }
        RunAsUser = $null
        Enabled   = $true
    })
}

foreach ($Item in @($WmiArtifact.Data)) {
    if ($null -eq $Item) { continue }
    $Persistence.Add([PSCustomObject]@{
        Source    = "WMIEventSubscription"
        Name      = $Item.ConsumerName
        Location  = $Item.EventNamespace
        Command   = $Item.CommandLine
        RunAsUser = $null
        Enabled   = $true
    })
}

Write-Log "Total persistence entries aggregated: $($Persistence.Count)"

# =========================
# Unified Persistence Schema
# =========================
$Summary = [PSCustomObject]@{
    ChainOfCustody = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=(Get-Date).ToString("o"); ToolVersion="1.0" }
    ArtifactType = "AutorunsPersistenceSummary"
    Hostname     = $Hostname
    GeneratedAt  = (Get-Date).ToString("o")
    ToolVersion="1.0"
    EntryCount   = $Persistence.Count
    Data         = $Persistence
}

$Summary | ConvertTo-Json -Depth 6 |
    Out-File -FilePath $OutputFile -Encoding UTF8

Write-Log "Persistence summary exported to JSON"

# =========================
# Evidence Integrity
# =========================
$Hash = Get-FileHash -Path $OutputFile -Algorithm SHA256

[PSCustomObject]@{
    FileName  = $OutputFile
    Algorithm = $Hash.Algorithm
    Hash      = $Hash.Hash
    Generated = (Get-Date).ToString("o")
} | ConvertTo-Json | Out-File -FilePath $HashFile -Encoding UTF8

Write-Log "SHA256 hash generated"

Write-Host "[+] Autoruns persistence summary created ($($Persistence.Count) entries)" -ForegroundColor Green
Write-Host "[+] JSON Output  : $OutputFile"  -ForegroundColor Green
Write-Host "[+] Hash Output  : $HashFile"    -ForegroundColor Green
Write-Host "[+] Execution Log: $LogFile"     -ForegroundColor Green

Write-Log "Script execution completed"
