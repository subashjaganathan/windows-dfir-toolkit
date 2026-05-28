#Requires -Version 5.1
Set-StrictMode -Off
$ErrorActionPreference = "Continue"
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
$LogFile  = "$BasePath\Logon_Sessions_Execution.log"
$JsonFile = "$BasePath\Logon_Sessions_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "Logon sessions deep collection started | Case: $CaseNum"

$DaysBack  = if ($env:DFIR_DAYS) { [int]$env:DFIR_DAYS } else { 30 }
$SinceDate = (Get-Date).AddDays(-$DaysBack)

# Event 4624 - Logon events with source IP and auth type
Write-Host "[*] Collecting detailed logon events (4624)..." -ForegroundColor Cyan
$LogonEvents = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $Filter = @{ LogName="Security"; Id=4624; StartTime=$SinceDate }
    $Events = @(Get-WinEvent -FilterHashtable $Filter -ErrorAction SilentlyContinue)
    foreach ($E in $Events) {
        $Msg = $E.Message
        $LogonType  = if ($Msg -match "Logon Type:\s*(\d+)") { $Matches[1] } else { $null }
        $SourceIP   = if ($Msg -match "Source Network Address:\s*(\S+)") { $Matches[1] } else { $null }
        $SourcePort = if ($Msg -match "Source Port:\s*(\S+)") { $Matches[1] } else { $null }
        $SubjectUser= if ($Msg -match "Subject:[\s\S]*?Account Name:\s*(\S+)") { $Matches[1] } else { $null }
        $TargetUser = if ($Msg -match "New Logon:[\s\S]*?Account Name:\s*(\S+)") { $Matches[1] } else { $null }
        $AuthPkg    = if ($Msg -match "Authentication Package:\s*(\S+)") { $Matches[1] } else { $null }
        $LogonProc  = if ($Msg -match "Logon Process:\s*(\S+)") { $Matches[1] } else { $null }
        $LogonID    = if ($Msg -match "New Logon:[\s\S]*?Logon ID:\s*(\S+)") { $Matches[1] } else { $null }
        $WorkStation= if ($Msg -match "Workstation Name:\s*(\S+)") { $Matches[1] } else { $null }

        $LogonTypeName = switch ($LogonType) {
            "2"  { "Interactive" }
            "3"  { "Network" }
            "4"  { "Batch" }
            "5"  { "Service" }
            "7"  { "Unlock" }
            "8"  { "NetworkCleartext" }
            "9"  { "NewCredentials" }
            "10" { "RemoteInteractive (RDP)" }
            "11" { "CachedInteractive" }
            "12" { "CachedRemoteInteractive" }
            "13" { "CachedUnlock" }
            default { "Unknown ($LogonType)" }
        }

        $IsSuspicious = $false
        $SuspReasons  = @()
        if ($LogonType -in @("3","9","10") -and $SourceIP -and $SourceIP -notmatch "^(127\.|::1|-$|0\.0\.0\.0)") {
            if ($TargetUser -match "Administrator|admin" -and $LogonType -eq "3") {
                $IsSuspicious = $true; $SuspReasons += "Network logon as admin account"
            }
        }
        if ($AuthPkg -eq "NTLM" -and $LogonType -eq "3") {
            $IsSuspicious = $true; $SuspReasons += "NTLM network authentication"
        }

        $LogonEvents.Add([PSCustomObject]@{
            TimeCreated  = $E.TimeCreated.ToString("o")
            EventID      = $E.Id
            LogonType    = $LogonType
            LogonTypeName= $LogonTypeName
            TargetUser   = $TargetUser
            SubjectUser  = $SubjectUser
            LogonID      = $LogonID
            SourceIP     = $SourceIP
            SourcePort   = $SourcePort
            WorkStation  = $WorkStation
            AuthPackage  = $AuthPkg
            LogonProcess = $LogonProc
            Computer     = $E.MachineName
            IsSuspicious = $IsSuspicious
            SuspiciousReasons = ($SuspReasons -join "; ")
        })
    }
    Write-Log "Logon events (4624): $($LogonEvents.Count)"
} catch { Write-Log "Logon event query failed: $_" "WARN" }

# Event 4634/4647 - Logoff events (for session duration)
Write-Host "[*] Collecting logoff events (4634/4647)..." -ForegroundColor Cyan
$LogoffEvents = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $Filter2 = @{ LogName="Security"; Id=@(4634,4647); StartTime=$SinceDate }
    $OffEvents = @(Get-WinEvent -FilterHashtable $Filter2 -ErrorAction SilentlyContinue)
    foreach ($E in $OffEvents) {
        $Msg     = $E.Message
        $LogonID = if ($Msg -match "Logon ID:\s*(\S+)") { $Matches[1] } else { $null }
        $User    = if ($Msg -match "Account Name:\s*(\S+)") { $Matches[1] } else { $null }
        $LogoffEvents.Add([PSCustomObject]@{
            TimeCreated = $E.TimeCreated.ToString("o")
            EventID     = $E.Id
            LogonID     = $LogonID
            User        = $User
        })
    }
    Write-Log "Logoff events: $($LogoffEvents.Count)"
} catch { Write-Log "Logoff event query failed: $_" "WARN" }

# Event 4625 - Failed logons
Write-Host "[*] Collecting failed logon events (4625)..." -ForegroundColor Cyan
$FailedLogons = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $Filter3 = @{ LogName="Security"; Id=4625; StartTime=$SinceDate }
    $FailEvents = @(Get-WinEvent -FilterHashtable $Filter3 -ErrorAction SilentlyContinue)
    foreach ($E in $FailEvents) {
        $Msg = $E.Message
        $FailedLogons.Add([PSCustomObject]@{
            TimeCreated  = $E.TimeCreated.ToString("o")
            TargetUser   = if ($Msg -match "Account Name:\s*(\S+)") { $Matches[1] } else { $null }
            SourceIP     = if ($Msg -match "Source Network Address:\s*(\S+)") { $Matches[1] } else { $null }
            FailureReason= if ($Msg -match "Failure Reason:\s*(.+?)(\r|\n|$)") { $Matches[1].Trim() } else { $null }
            LogonType    = if ($Msg -match "Logon Type:\s*(\d+)") { $Matches[1] } else { $null }
        })
    }
    Write-Log "Failed logons (4625): $($FailedLogons.Count)"
} catch { Write-Log "Failed logon query failed: $_" "WARN" }

# Live sessions via query session
Write-Host "[*] Collecting live session information..." -ForegroundColor Cyan
$LiveSessions = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $QSession = (query session 2>&1) -join "`n"
    $QSession -split "`n" | Select-Object -Skip 1 | ForEach-Object {
        if ($_ -match "(\S+)\s+(\S+)\s+(\d+)\s+(\w+)\s*(.*)") {
            $LiveSessions.Add([PSCustomObject]@{
                SessionName = $Matches[1]
                UserName    = $Matches[2]
                SessionID   = $Matches[3]
                State       = $Matches[4]
                Type        = $Matches[5].Trim()
            })
        }
    }
} catch { Write-Log "query session failed: $_" "WARN" }

# Brute force detection - more than 5 failures from same IP
$BruteForceIPs = @($FailedLogons |
    Where-Object { $_.SourceIP -and $_.SourceIP -notmatch "^(127\.|::1|-|0\.0\.0\.0)" } |
    Group-Object SourceIP |
    Where-Object { $_.Count -ge 5 } |
    ForEach-Object { [PSCustomObject]@{ SourceIP=$_.Name; FailCount=$_.Count } })

$SuspiciousLogons = @($LogonEvents | Where-Object { $_.IsSuspicious }).Count
Write-Log "Logons: $($LogonEvents.Count) | Failed: $($FailedLogons.Count) | BruteForce IPs: $($BruteForceIPs.Count) | Suspicious: $SuspiciousLogons"

$Evidence = [PSCustomObject]@{
    ChainOfCustody     = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=(Get-Date).ToString("o"); ToolVersion="1.0" }
    ArtifactType       = "Logon_Sessions_Deep"
    LogonCount         = $LogonEvents.Count
    FailedLogonCount   = $FailedLogons.Count
    SuspiciousLogons   = $SuspiciousLogons
    BruteForceIPCount  = $BruteForceIPs.Count
    LiveSessionCount   = $LiveSessions.Count
    BruteForceIPs      = $BruteForceIPs
    LiveSessions       = $LiveSessions
    LogonEvents        = $LogonEvents
    LogoffEvents       = $LogoffEvents
    FailedLogons       = $FailedLogons
}

$Evidence | ConvertTo-Json -Depth 6 | Out-File $JsonFile -Encoding UTF8
$Hash = Get-FileHash $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=(Get-Date).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] Logon sessions complete | Logons: $($LogonEvents.Count) | Failed: $($FailedLogons.Count) | Brute Force IPs: $($BruteForceIPs.Count) | Suspicious: $SuspiciousLogons" -ForegroundColor Green
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed"
