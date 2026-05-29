#Requires -Version 5.1
<#
.SYNOPSIS
    Collects critical Windows Security Event Log entries.

.DESCRIPTION
    Exports high-value Security events: logon/logoff, account
    management, privilege use, process creation, and policy changes.
    Covers the most important event IDs for IR investigations.

.IR_PHASE
    Identification / Investigation

.MITRE_ATTCK
    T1078  - Valid Accounts
    T1136  - Create Account
    T1098  - Account Manipulation
    T1059  - Command and Scripting Interpreter
    T1548  - Abuse Elevation Control

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
if (-not $IsAdmin) { Write-Warning "[!] Administrator privileges required for full event log access." }

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
$LogFile  = "$BasePath\Security_EventLog_Execution.log"
$JsonFile = "$BasePath\Security_EventLog_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }

# High-value Security event IDs with descriptions
$EventMap = @{
    # Logon/Logoff
    4624 = "Logon Success"
    4625 = "Logon Failure"
    4634 = "Logoff"
    4647 = "User Initiated Logoff"
    4648 = "Logon with Explicit Credentials"
    4672 = "Special Privileges Assigned"
    4778 = "Session Reconnected"
    4779 = "Session Disconnected"
    # Account Management
    4720 = "User Account Created"
    4722 = "User Account Enabled"
    4723 = "Password Change Attempt"
    4724 = "Password Reset"
    4725 = "User Account Disabled"
    4726 = "User Account Deleted"
    4728 = "Member Added to Global Group"
    4732 = "Member Added to Local Group"
    4756 = "Member Added to Universal Group"
    4738 = "User Account Changed"
    4740 = "User Account Locked Out"
    4767 = "User Account Unlocked"
    # Process
    4688 = "Process Created"
    4689 = "Process Exited"
    # Policy / Audit
    4698 = "Scheduled Task Created"
    4699 = "Scheduled Task Deleted"
    4700 = "Scheduled Task Enabled"
    4701 = "Scheduled Task Disabled"
    4702 = "Scheduled Task Updated"
    4719 = "Audit Policy Changed"
    4946 = "Firewall Rule Added"
    4947 = "Firewall Rule Modified"
    4950 = "Firewall Setting Changed"
    # Credential / Kerberos
    4768 = "Kerberos TGT Request"
    4769 = "Kerberos Service Ticket Request"
    4771 = "Kerberos Pre-Auth Failed"
    4776 = "NTLM Auth Attempt"
    # Object Access
    4663 = "Object Access Attempt"
    4670 = "Permissions Changed"
    # Service
    7045 = "New Service Installed"
    7036 = "Service State Changed"
}

$TargetIDs = $EventMap.Keys

Write-Log "Security event log collection started | Case: $CaseNum"
Write-Host "[*] Collecting Security Event Log (EventIDs: $($TargetIDs.Count) types)..." -ForegroundColor Cyan

# Look back 30 days by default, override with $env:DFIR_DAYS
$DaysBack  = if ($env:DFIR_DAYS) { [int]$env:DFIR_DAYS } else { 30 }
$StartTime  = (Get-Date).AddDays(-$DaysBack)

Write-Log "Time window: last $DaysBack days (since $($StartTime.ToString('o')))"

$AllEvents = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($ID in $TargetIDs) {
    try {
        $LogName = if ($ID -ge 7000) { "System" } else { "Security" }
        $Filter = @{
            LogName   = $LogName
            Id        = $ID
            StartTime = $StartTime
        }
        $Events = Get-WinEvent -FilterHashtable $Filter -ErrorAction SilentlyContinue
        foreach ($Evt in $Events) {
            $AllEvents.Add([PSCustomObject]@{
                TimeCreated  = $Evt.TimeCreated.ToString("o")
                EventID      = $Evt.Id
                EventType    = $EventMap[$Evt.Id]
                Level        = $Evt.LevelDisplayName
                LogName      = $Evt.LogName
                ProviderName = $Evt.ProviderName
                Computer     = $Evt.MachineName
                UserSID      = $Evt.UserId
                Message      = ($Evt.Message -split "`r?`n" -join " ").Substring(0, [Math]::Min(500, $Evt.Message.Length))
                RecordID     = $Evt.RecordId
            })
        }
        if ($Events.Count -gt 0) { Write-Log "EventID $ID ($($EventMap[$ID])): $($Events.Count) events" }
    } catch {
        Write-Log "ERROR on EventID ${ID}: $_" "ERROR"
    }
}

# Sort by time
$Sorted = $AllEvents | Sort-Object TimeCreated -Descending

Write-Log "Total security events collected: $($Sorted.Count)"

$Evidence = [PSCustomObject]@{
    ChainOfCustody = [PSCustomObject]@{
        CaseNumber  = $CaseNum
        Hostname    = $Hostname
        CollectedAt = (Get-Date).ToString("o")
        ToolVersion="1.0"
        DaysBack    = $DaysBack
    }
    ArtifactType = "SecurityEventLog"
    EventCount   = $Sorted.Count
    TimeWindow   = [PSCustomObject]@{ Start = $StartTime.ToString("o"); End = (Get-Date).ToString("o") }
    EventIDSummary = ($AllEvents | Group-Object EventID | Sort-Object Count -Descending |
        ForEach-Object { [PSCustomObject]@{ EventID=$_.Name; Type=$EventMap[[int]$_.Name]; Count=$_.Count } })
    Data         = $Sorted
}

$Evidence | ConvertTo-Json -Depth 5 -Compress | Out-File -FilePath $JsonFile -Encoding UTF8
$Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=(Get-Date).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Log "Exported to $JsonFile"
Write-Host "[+] Security Event Log collection complete ($($Sorted.Count) events)" -ForegroundColor Green
Write-Host "[+] JSON : $JsonFile" -ForegroundColor Green
Write-Log "Completed"
