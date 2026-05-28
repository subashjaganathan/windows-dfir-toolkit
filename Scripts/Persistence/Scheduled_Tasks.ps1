<#
.SYNOPSIS
    Collects scheduled tasks to identify persistence mechanisms.

.DESCRIPTION
    Enumerates Windows scheduled tasks and extracts execution
    commands, triggers, run context, and last-run timestamps
    to detect malicious persistence techniques.

.IR_PHASE
    Persistence / Investigation

.MITRE_ATTCK
    T1053.005 - Scheduled Task
    T1059    - Command-Line / PowerShell
    T1106    - Native API
    T1036    - Masquerading

.FORENSIC_SAFETY
    Read-only, forensic-safe

.OUTPUT
    JSON evidence file + SHA256 hash
    Execution log

.AUTHOR
    DFIR Toolkit

.VERSION
    1.1
#>

Set-StrictMode -Off
$ErrorActionPreference = "Continue"

# =========================
# Privilege Awareness
# =========================
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# =========================
# Environment / Paths
# =========================
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$LogFile   = "$BasePath\ScheduledTasks_Execution.log"

New-Item -ItemType Directory -Path $BasePath -Force | Out-Null

function Write-Log {
    param([string]$Message)
    Add-Content -Path $LogFile -Value "$(Get-Date -Format o) :: $Message"
}

Write-Log "Scheduled task collection started"
Write-Log "Administrator privileges: $IsAdmin"

if (-not $IsAdmin) {
    Write-Warning "[!] Administrator privileges recommended for full scheduled task visibility."
}

# =========================
# Task Info Collection
# FIX: v1.0 did not capture LastRunTime, LastTaskResult, or NextRunTime
# FIX: TriggerType used $_.TriggerType which doesn't exist; correct property is CimClass.CimClassName
# =========================
Write-Host "[*] Collecting scheduled tasks..." -ForegroundColor Cyan
Write-Log "Enumerating scheduled tasks"

$Tasks = Get-ScheduledTask -ErrorAction SilentlyContinue

# Get task run history via ScheduledTaskInfo
$TaskInfoMap = @{}
Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
    try {
        $Info = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
        if ($Info) {
            $Key = "$($_.TaskPath)$($_.TaskName)"
            $TaskInfoMap[$Key] = $Info
        }
    } catch {}
}

$TaskData = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($Task in $Tasks) {

    $Key      = "$($Task.TaskPath)$($Task.TaskName)"
    $TaskInfo = $TaskInfoMap[$Key]

    # Collect trigger summary
    $TriggerSummary = @($Task.Triggers | ForEach-Object {
        $_.CimClass.CimClassName -replace "^MSFT_Task", ""
    }) -join ", "

    foreach ($Action in $Task.Actions) {

        if ($TaskInfo.LastRunTime -and $TaskInfo.LastRunTime -ne [datetime]::MinValue) {
            $LastRunTimeStr = $TaskInfo.LastRunTime.ToString("o")
        } else { $LastRunTimeStr = $null }
        if ($TaskInfo) { $LastTaskResultStr = "0x{0:X8}" -f $TaskInfo.LastTaskResult } else { $LastTaskResultStr = $null }
        if ($TaskInfo.NextRunTime -and $TaskInfo.NextRunTime -ne [datetime]::MinValue) {
            $NextRunTimeStr = $TaskInfo.NextRunTime.ToString("o")
        } else { $NextRunTimeStr = $null }

        $TaskData.Add([PSCustomObject]@{
            Hostname        = $Hostname
            CollectionTime  = (Get-Date).ToString("o")
            TaskName        = $Task.TaskName
            TaskPath        = $Task.TaskPath
            State           = $Task.State.ToString()
            RunAsUser       = $Task.Principal.UserId
            LogonType       = $Task.Principal.LogonType.ToString()
            RunLevel        = $Task.Principal.RunLevel.ToString()   # FIX: added - flags HIGHEST vs LIMITED
            Command         = $Action.Execute
            Arguments       = $Action.Arguments
            WorkingDir      = $Action.WorkingDirectory              # FIX: added working directory
            TriggerTypes    = $TriggerSummary
            LastRunTime     = $LastRunTimeStr
            LastTaskResult  = $LastTaskResultStr
            NextRunTime     = $NextRunTimeStr
            Author          = $Task.Author                          # FIX: added author field
        })
    }
}

Write-Log "Scheduled tasks collected: $($TaskData.Count) actions across $($Tasks.Count) tasks"

# =========================
# Unified Evidence Schema
# =========================
$JsonFile = "$BasePath\Scheduled_Tasks_${Hostname}_${Timestamp}.json"
$HashFile = "$JsonFile.hash.json"

$Evidence = [PSCustomObject]@{
    ArtifactType = "ScheduledTasks"
    Hostname     = $Hostname
    CollectedAt  = (Get-Date).ToString("o")
    ToolVersion="1.0"
    TaskCount    = $TaskData.Count
    Data         = $TaskData
}

$Evidence | ConvertTo-Json -Depth 6 |
    Out-File -FilePath $JsonFile -Encoding UTF8

Write-Log "Scheduled tasks exported to JSON"

# =========================
# Evidence Integrity
# =========================
$Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256

[PSCustomObject]@{
    FileName  = $JsonFile
    Algorithm = $Hash.Algorithm
    Hash      = $Hash.Hash
    Generated = (Get-Date).ToString("o")
} | ConvertTo-Json | Out-File -FilePath $HashFile -Encoding UTF8

Write-Log "SHA256 hash generated"

Write-Host "[+] Scheduled task collection completed ($($TaskData.Count) entries)" -ForegroundColor Green
Write-Host "[+] JSON Output  : $JsonFile"  -ForegroundColor Green
Write-Host "[+] Hash Output  : $HashFile"  -ForegroundColor Green
Write-Host "[+] Execution Log: $LogFile"   -ForegroundColor Green

Write-Log "Script execution completed"
