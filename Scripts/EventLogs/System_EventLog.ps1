#Requires -Version 5.1
<#
.SYNOPSIS
    Collects System, Application, and key operational event logs.

.DESCRIPTION
    Targets service installs (7045), driver loads, crash events,
    Windows Defender, Task Scheduler, WMI activity, RDP, and
    application errors relevant to IR investigations.

.IR_PHASE
    Identification / Investigation

.MITRE_ATTCK
    T1543.003 - Windows Service
    T1562.001 - Disable Security Tools
    T1059     - Command and Scripting Interpreter

.FORENSIC_SAFETY
    Read-only, forensic-safe

.AUTHOR
    DFIR Toolkit

.VERSION
    2.0
#>

Set-StrictMode -Off
$ErrorActionPreference = "Continue"
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
$LogFile  = "$BasePath\System_EventLog_Execution.log"
$JsonFile = "$BasePath\System_EventLog_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "System/App event log collection started"

$DaysBack  = if ($env:DFIR_DAYS) { [int]$env:DFIR_DAYS } else { 30 }
$StartTime = (Get-Date).AddDays(-$DaysBack)

$LogTargets = @(
    @{ LogName="System";      IDs=@(7045,7036,7040,6005,6006,6008,1074,41);    Label="System" }
    @{ LogName="Application"; IDs=@(1000,1001,1002);                            Label="AppCrash" }
    @{ LogName="Microsoft-Windows-TaskScheduler/Operational"; IDs=@(106,140,141,200,201,325); Label="TaskScheduler" }
    @{ LogName="Microsoft-Windows-WMI-Activity/Operational";  IDs=@(5857,5858,5859,5860,5861); Label="WMI" }
    @{ LogName="Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"; IDs=@(21,22,23,24,25); Label="RDP" }
    @{ LogName="Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"; IDs=@(1149); Label="RDPRemote" }
    @{ LogName="Microsoft-Windows-Windows Defender/Operational"; IDs=@(1006,1007,1008,1009,1116,1117,1118,1119,5001,5004,5007,5010,5012); Label="Defender" }
    @{ LogName="Microsoft-Windows-Bits-Client/Operational"; IDs=@(3,4,59,60,61); Label="BITS" }
    @{ LogName="Microsoft-Windows-AppLocker/EXE and DLL"; IDs=@(8003,8004,8006,8007); Label="AppLocker" }
)

$AllGroups = [ordered]@{}

foreach ($Target in $LogTargets) {
    Write-Host "[*] Collecting $($Target.Label) events..." -ForegroundColor Cyan
    $Events = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        $RawEvents = Get-WinEvent -FilterHashtable @{
            LogName   = $Target.LogName
            Id        = $Target.IDs
            StartTime = $StartTime
        } -ErrorAction SilentlyContinue

        foreach ($Evt in $RawEvents) {
            $Events.Add([PSCustomObject]@{
                TimeCreated  = $Evt.TimeCreated.ToString("o")
                EventID      = $Evt.Id
                Level        = $Evt.LevelDisplayName
                Source       = $Evt.ProviderName
                Computer     = $Evt.MachineName
                Message      = ($Evt.Message -split "`r?`n" -join " ").Substring(0,[Math]::Min(800,$Evt.Message.Length))
                RecordID     = $Evt.RecordId
            })
        }
        Write-Log "$($Target.Label): $($Events.Count) events"
    } catch {
        Write-Log "Could not query $($Target.LogName): $_" "WARN"
    }
    $AllGroups[$Target.Label] = $Events
}

# -- Event Log Config / Audit Policy -------------------------------------------
Write-Host "[*] Checking audit policy config..." -ForegroundColor Cyan
$AuditPolicy = (auditpol /get /category:* 2>&1) -join "`n"

$Evidence = [PSCustomObject]@{
    ChainOfCustody = [PSCustomObject]@{
        CaseNumber  = $CaseNum; Hostname = $Hostname
        CollectedAt = (Get-Date).ToString("o"); ToolVersion="1.0"; DaysBack = $DaysBack
    }
    ArtifactType = "SystemApplicationEventLog"
    AuditPolicy  = $AuditPolicy
    EventGroups  = $AllGroups
}

$Evidence | ConvertTo-Json -Depth 5 -Compress | Out-File -FilePath $JsonFile -Encoding UTF8
$Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=(Get-Date).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

$TotalEvents = ($AllGroups.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
Write-Host "[+] System/App event collection complete ($TotalEvents total events)" -ForegroundColor Green
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed"
