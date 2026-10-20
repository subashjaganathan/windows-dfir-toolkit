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


# --- Shared toolkit module: single source of truth for version + base paths ---
$__DFIRMod = Join-Path $PSScriptRoot '..\Infrastructure\DFIR_Common.psm1'
if (Test-Path $__DFIRMod) { Import-Module $__DFIRMod -Force -ErrorAction SilentlyContinue }
if (-not $Global:DFIR_ToolVersion) { $Global:DFIR_ToolVersion = '1.0' }
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

# --- Structured event fields ---------------------------------------------------
# The rendered Message was the only payload before, cut at 500 characters - a 4624
# message is ~3,000, so account, logon type and source IP (all after the cut) were lost.
function Get-EventFields($Evt) {
    $h = [ordered]@{}
    try {
        # Walk real XML nodes: PowerShell's dot-notation returns bare strings for <Data>
        # elements without attributes, and classic events (7036, 7045 ...) use UNNAMED
        # <Data> elements - those become param1..N.
        $x = [xml]$Evt.ToXml()
        $i = 0
        foreach ($n in @($x.DocumentElement.ChildNodes | Where-Object { $_.LocalName -eq 'EventData' } | ForEach-Object { $_.ChildNodes })) {
            if ($n.NodeType -ne 'Element' -or $n.LocalName -ne 'Data') { continue }
            $i++
            $name = $n.GetAttribute('Name')
            $h[$(if ($name) { $name } else { "param$i" })] = $n.InnerText
        }
        if (-not $h.Count) {
            $ud = $x.DocumentElement.ChildNodes | Where-Object { $_.LocalName -eq 'UserData' } | Select-Object -First 1
            if ($ud -and $ud.FirstChild) { foreach ($n in @($ud.FirstChild.ChildNodes)) { if ($n.NodeType -eq 'Element') { $h[$n.LocalName] = $n.InnerText } } }
        }
    } catch {}
    $h
}

$LogonTypes = @{ '2'='Interactive'; '3'='Network'; '4'='Batch'; '5'='Service'; '7'='Unlock'; '8'='NetworkCleartext';
                 '9'='NewCredentials'; '10'='RemoteInteractive (RDP)'; '11'='CachedInteractive' }

# One readable line per event for the report and timeline.
function Get-EventSummary([int]$Id, $D) {
    $acct = { param($u, $dom) if ($u -and $u -ne '-') { if ($dom -and $dom -ne '-') { "$dom\$u" } else { $u } } }
    $tgt = & $acct $D.TargetUserName $D.TargetDomainName
    $sub = & $acct $D.SubjectUserName $D.SubjectDomainName
    $src = @($D.IpAddress, $D.WorkstationName) | Where-Object { $_ -and $_ -notin '-', '::1', '127.0.0.1' } | Select-Object -First 1
    $lt  = if ($D.LogonType) { "type $($D.LogonType) $($LogonTypes["$($D.LogonType)"])" }
    switch ($Id) {
        { $_ -in 4624, 4625 } { return ("{0} {1}{2}{3}" -f $(if ($Id -eq 4624) { 'Logon' } else { 'FAILED logon' }), $tgt, $(if ($lt) { " ($lt)" }), $(if ($src) { " from $src" })) + $(if ($Id -eq 4625 -and $D.Status) { " status $($D.Status)/$($D.SubStatus)" }) }
        4648 { return "Explicit credentials: $sub used $tgt for $($D.TargetServerName) via $($D.ProcessName)" }
        { $_ -in 4634, 4647 } { return "Logoff $tgt" }
        4672 { return "Special privileges assigned to $sub" }
        { $_ -in 4720, 4722, 4725, 4726, 4738, 4740, 4767 } { return "$($EventMap[$Id]): $tgt by $sub" }
        { $_ -in 4723, 4724 } { return "$($EventMap[$Id]): $tgt by $sub" }
        { $_ -in 4728, 4732, 4756 } { return "$($D.MemberName) added to group $($D.TargetUserName) by $sub" }
        4688 { return "Process $($D.NewProcessName) by $sub (parent $($D.ParentProcessName)) $($D.CommandLine)".Trim() }
        { $_ -in 4698, 4699, 4700, 4701, 4702 } { return "$($EventMap[$Id]): $($D.TaskName) by $sub" }
        { $_ -in 4768, 4769 } { return "$($EventMap[$Id]): $tgt service $($D.ServiceName) enc $($D.TicketEncryptionType) from $($D.IpAddress) status $($D.Status)" }
        4771 { return "Kerberos pre-auth FAILED: $tgt from $($D.IpAddress) status $($D.Status)" }
        4776 { return "NTLM validation: $tgt from $($D.Workstation) status $($D.Status)" }
        7045 { return "Service installed: $($D.ServiceName) -> $($D.ImagePath) as $($D.AccountName)" }
        7036 { return "Service $($D.param1) entered the $($D.param2) state" }
        default { return "$($EventMap[$Id])$(if ($sub) { " by $sub" })" }
    }
}

# Indicators that are well-founded on their own (convergence analysis happens in the report).
function Get-EventFlag([int]$Id, $D) {
    $enc = "$($D.TicketEncryptionType)".ToLowerInvariant()
    switch ($Id) {
        4625 { return "failed logon" }
        4648 { if ($D.TargetServerName -and $D.TargetServerName -notin 'localhost', '-', $env:COMPUTERNAME) { return "explicit credentials to remote host $($D.TargetServerName)" } }
        4769 { if ($enc -in '0x17', '0x18' -and "$($D.ServiceName)" -notmatch '\$$|^krbtgt$') { return "RC4 service ticket for a user SPN (Kerberoasting indicator)" } }
        4768 { if ($enc -in '0x17', '0x18', '0x1', '0x3') { return "TGT with weak (RC4/DES) encryption" } }
        4771 { return "Kerberos pre-authentication failure" }
        4776 { if ($D.Status -and $D.Status -ne '0x0') { return "NTLM authentication failure ($($D.Status))" } }
        4720 { return "user account created" }
        { $_ -in 4728, 4732, 4756 } { if ("$($D.TargetUserName)" -match 'Admin|Operators|Remote Desktop Users|Remote Management Users') { return "member added to privileged group $($D.TargetUserName)" } }
        4719 { return "audit policy changed" }
    }
    $null
}

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
            $D = Get-EventFields $Evt
            $Flag = Get-EventFlag $Evt.Id $D
            $Msg = if ($Evt.Message) { $Evt.Message -split "`r?`n" -join " " } else { "" }
            $AllEvents.Add([PSCustomObject]@{
                TimeCreated  = $Evt.TimeCreated.ToUniversalTime().ToString("o")
                EventID      = $Evt.Id
                EventType    = $EventMap[$Evt.Id]
                Summary      = Get-EventSummary $Evt.Id $D
                Level        = $Evt.LevelDisplayName
                LogName      = $Evt.LogName
                ProviderName = $Evt.ProviderName
                Computer     = $Evt.MachineName
                # Security events carry the account in EventData, not in the System UserID.
                UserSID      = if ($Evt.UserId) { "$($Evt.UserId)" } elseif ($D.TargetUserSid) { $D.TargetUserSid } elseif ($D.SubjectUserSid) { $D.SubjectUserSid } else { $null }
                IsSuspicious = [bool]$Flag
                SuspiciousReason = $Flag
                EventData    = [PSCustomObject]$D       # every field, structured - nothing lost to truncation
                Message      = $Msg.Substring(0, [Math]::Min(500, $Msg.Length))
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
        CollectedAt = ([DateTime]::UtcNow).ToString("o")
        ToolVersion=$Global:DFIR_ToolVersion
        DaysBack    = $DaysBack
    }
    ArtifactType = "SecurityEventLog"
    EventCount   = $Sorted.Count
    TimeWindow   = [PSCustomObject]@{ Start = $StartTime.ToString("o"); End = ([DateTime]::UtcNow).ToString("o") }
    EventIDSummary = ($AllEvents | Group-Object EventID | Sort-Object Count -Descending |
        ForEach-Object { [PSCustomObject]@{ EventID=$_.Name; Type=$EventMap[[int]$_.Name]; Count=$_.Count } })
    Data         = $Sorted
}

$Evidence | ConvertTo-Json -Depth 6 -Compress | Out-File -FilePath $JsonFile -Encoding UTF8
$Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=([DateTime]::UtcNow).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Log "Exported to $JsonFile"
Write-Host "[+] Security Event Log collection complete ($($Sorted.Count) events)" -ForegroundColor Green
Write-Host "[+] JSON : $JsonFile" -ForegroundColor Green
Write-Log "Completed"
