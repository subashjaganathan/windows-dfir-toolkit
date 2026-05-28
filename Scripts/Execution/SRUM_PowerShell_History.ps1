#Requires -Version 5.1
<#
.SYNOPSIS
    Collects SRUM database, PowerShell history, and execution history artifacts.
    On Server OS, adds Windows Server-specific execution evidence.

.DESCRIPTION
    Workstation (Win10/11):
      - SRUM DB copy (30-60 days of app/network usage)
      - PSReadLine command history per user
      - Windows Timeline ActivitiesCache.db
      - Run/TypedPaths MRU

    Server (2016/2019/2022) additional artifacts:
      - Scheduled task execution history from event log
      - Service start/stop history
      - Remote PowerShell session history (WinRM)
      - Script execution via Task Scheduler logs
      - Server Manager activity log

.COMPATIBILITY
    Windows 10/11   : Full
    Server 2016+    : Full with server-specific additions

.IR_PHASE
    Execution Evidence / User Activity

.MITRE_ATTCK
    T1059.001 - PowerShell
    T1053     - Scheduled Task
    T1204     - User Execution

.FORENSIC_SAFETY
    Read-only - SRUM DB copied via esentutl

.AUTHOR
    DFIR Toolkit

.VERSION
    2.1
#>

Set-StrictMode -Off
$ErrorActionPreference = "Continue"
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) { Write-Warning "[!] Administrator privileges required to access SRUM database." }

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
$DaysBack  = if ($env:DFIR_DAYS) { [int]$env:DFIR_DAYS } else { 30 }
$OutDir    = "$BasePath\SRUM_History_${Hostname}_${Timestamp}"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$LogFile   = "$BasePath\SRUM_History_Execution.log"
$JsonFile  = "$BasePath\SRUM_History_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "SRUM/History collection started | Case: $CaseNum"

# -- OS Detection --------------------------------------------------------------
$OSInfo    = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$OSCaption = $OSInfo.Caption
$IsServer  = $OSCaption -match "Server"
$OSBuild   = [int]$OSInfo.BuildNumber
Write-Log "OS: $OSCaption | IsServer: $IsServer | DaysBack: $DaysBack"

# -- SRUM Database (all OS) ----------------------------------------------------
Write-Host "[*] Locating SRUM database..." -ForegroundColor Cyan
$SRUMPath = "C:\Windows\System32\sru\SRUDB.dat"
$SRUMInfo = [PSCustomObject]@{ Collected = $false }

if (Test-Path $SRUMPath) {
    try {
        $SRUMFile = Get-Item $SRUMPath
        $CopyDest = "$OutDir\SRUDB.dat"
        $EsentOut = (& cmd.exe /c "esentutl.exe /y `"$SRUMPath`" /d `"$CopyDest`" /o" 2>&1) -join " "
        $CopiedOK = Test-Path $CopyDest
        $SRUMInfo = [PSCustomObject]@{
            Collected      = $true
            SourcePath     = $SRUMPath
            SizeBytes      = $SRUMFile.Length
            LastModified   = $SRUMFile.LastWriteTimeUtc.ToString("o")
            CopiedTo       = if ($CopiedOK) { $CopyDest } else { $null }
            CopySucceeded  = $CopiedOK
            IsServerOS     = $IsServer
            ServerNote     = if ($IsServer) { "SRUM on Server has less app data but still records network usage and task execution" } else { $null }
            ParseNote      = "Use srum-dump (https://github.com/MarkBaggett/srum-dump) for full parsing"
        }
        Write-Log ("SRUM copied: " + $CopiedOK + " | Size: " + $SRUMFile.Length)
    } catch {
        $SRUMInfo = [PSCustomObject]@{ Collected=$false; Error="SRUM copy failed: $_" }
        Write-Log "SRUM copy error: $_" "WARN"
    }
} else {
    $SRUMInfo = [PSCustomObject]@{ Collected=$false; Note="SRUM database not found at $SRUMPath" }
    Write-Log "SRUM not found" "WARN"
}

# -- PowerShell History (all OS) -----------------------------------------------
Write-Host "[*] Collecting PowerShell history files..." -ForegroundColor Cyan
$PSHistories = [System.Collections.Generic.List[PSCustomObject]]::new()
$SuspPatterns = @("invoke-expression","iex ","encodedcommand","-enc ","-e ",
                  "downloadstring","webclient","frombase64","bypass","mimikatz",
                  "invoke-mimikatz","amsibypass","reflective","new-object net.webclient")

Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $HistPath = "$($_.FullName)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $HistPath) {
        $Lines    = @(Get-Content $HistPath -ErrorAction SilentlyContinue)
        $CopyDest = "$OutDir\PSHistory_$($_.Name).txt"
        Copy-Item $HistPath $CopyDest -Force -ErrorAction SilentlyContinue
        $SuspLines = @($Lines | Where-Object { $L = $_.ToLower(); $SuspPatterns | Where-Object { $L -match $_ } })
        $PSHistories.Add([PSCustomObject]@{
            UserProfile        = $_.Name
            HistoryFilePath    = $HistPath
            CopiedTo           = $CopyDest
            TotalCommands      = $Lines.Count
            SuspiciousCount    = $SuspLines.Count
            SuspiciousCommands = $SuspLines
            AllCommands        = $Lines
        })
        Write-Log ("PS History " + $_.Name + ": " + $Lines.Count + " commands, " + $SuspLines.Count + " suspicious")
    }
}

# -- Windows Timeline (Workstation only) ----------------------------------------
$TimelineDBs = [System.Collections.Generic.List[PSCustomObject]]::new()
if (-not $IsServer) {
    Write-Host "[*] Locating Windows Timeline databases..." -ForegroundColor Cyan
    Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $TimelinePath = "$($_.FullName)\AppData\Local\ConnectedDevicesPlatform"
        if (Test-Path $TimelinePath) {
            Get-ChildItem $TimelinePath -Recurse -Filter "ActivitiesCache.db" -ErrorAction SilentlyContinue | ForEach-Object {
                $CopyDest = "$OutDir\ActivitiesCache_$($_.Name)_$(Get-Random).db"
                Copy-Item $_.FullName $CopyDest -Force -ErrorAction SilentlyContinue
                $TimelineDBs.Add([PSCustomObject]@{
                    SourcePath   = $_.FullName
                    CopiedTo     = if (Test-Path $CopyDest) { $CopyDest } else { $null }
                    SizeBytes    = $_.Length
                    LastModified = $_.LastWriteTimeUtc.ToString("o")
                    ParseNote    = "Use WxTCmd.exe (Eric Zimmerman) for full timeline parsing"
                })
            }
        }
    }
    Write-Log "Timeline DBs: $($TimelineDBs.Count)"
}

# -- CMD / Run Dialog History (all OS) -----------------------------------------
Write-Host "[*] Collecting CMD and Run dialog history..." -ForegroundColor Cyan
$CMDHistory = [System.Collections.Generic.List[PSCustomObject]]::new()
$RunMRU = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -ErrorAction SilentlyContinue
if ($RunMRU) {
    $RunMRU.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS|MRUList" } | ForEach-Object {
        $CMDHistory.Add([PSCustomObject]@{ Source="RunDialog"; Key=$_.Name; Command=$_.Value })
    }
}
$TypedPaths = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" -ErrorAction SilentlyContinue
if ($TypedPaths) {
    $TypedPaths.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
        $CMDHistory.Add([PSCustomObject]@{ Source="ExplorerBar"; Key=$_.Name; Command=$_.Value })
    }
}
Write-Log "CMD/Run history: $($CMDHistory.Count)"

# -- SERVER-SPECIFIC: Additional execution artifacts ---------------------------
$ServerArtifacts = [PSCustomObject]@{ Collected = $false }

if ($IsServer) {
    Write-Host "[*] Server OS - collecting server-specific execution artifacts..." -ForegroundColor Cyan
    Write-Log "Collecting server-specific execution artifacts"

    $StartTime = (Get-Date).AddDays(-$DaysBack)

    # Scheduled Task execution history from event log
    $TaskExecEvents = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        $TEvents = Get-WinEvent -FilterHashtable @{
            LogName   = "Microsoft-Windows-TaskScheduler/Operational"
            Id        = @(200, 201, 106, 140, 141)
            StartTime = $StartTime
        } -ErrorAction SilentlyContinue

        foreach ($E in $TEvents) {
            $TaskExecEvents.Add([PSCustomObject]@{
                TimeCreated = $E.TimeCreated.ToString("o")
                EventID     = $E.Id
                EventType   = switch ($E.Id) { 200{"Task Started"} 201{"Task Completed"} 106{"Task Registered"} 140{"Task Updated"} 141{"Task Deleted"} }
                Message     = ($E.Message -replace '\r?\n',' ').Substring(0,[Math]::Min(300,$E.Message.Length))
            })
        }
        Write-Log "Task execution events: $($TaskExecEvents.Count)"
    } catch { Write-Log "Task exec events failed: $_" "WARN" }

    # Remote PS / WinRM session history
    $WinRMEvents = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        $WREvents = Get-WinEvent -FilterHashtable @{
            LogName   = "Microsoft-Windows-WinRM/Operational"
            Id        = @(6, 8, 15, 16, 33)
            StartTime = $StartTime
        } -ErrorAction SilentlyContinue

        foreach ($E in $WREvents) {
            $WinRMEvents.Add([PSCustomObject]@{
                TimeCreated = $E.TimeCreated.ToString("o")
                EventID     = $E.Id
                Message     = ($E.Message -replace '\r?\n',' ').Substring(0,[Math]::Min(300,$E.Message.Length))
            })
        }
        Write-Log "WinRM events: $($WinRMEvents.Count)"
    } catch { Write-Log "WinRM events failed: $_" "WARN" }

    # Service install/start history (execution via services)
    $ServiceExecEvents = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        $SvcEvents = Get-WinEvent -FilterHashtable @{
            LogName   = "System"
            Id        = @(7045, 7036, 7040)
            StartTime = $StartTime
        } -ErrorAction SilentlyContinue

        foreach ($E in $SvcEvents) {
            $ServiceExecEvents.Add([PSCustomObject]@{
                TimeCreated = $E.TimeCreated.ToString("o")
                EventID     = $E.Id
                EventType   = switch ($E.Id) { 7045{"Service Installed"} 7036{"Service State Changed"} 7040{"Service Start Type Changed"} }
                Message     = ($E.Message -replace '\r?\n',' ').Substring(0,[Math]::Min(300,$E.Message.Length))
            })
        }
        Write-Log "Service execution events: $($ServiceExecEvents.Count)"
    } catch { Write-Log "Service events failed: $_" "WARN" }

    # Windows Server roles installed
    $ServerRoles = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        $Roles = Get-WindowsFeature -ErrorAction SilentlyContinue | Where-Object { $_.Installed }
        foreach ($Role in $Roles) {
            $ServerRoles.Add([PSCustomObject]@{
                Name         = $Role.Name
                DisplayName  = $Role.DisplayName
                FeatureType  = $Role.FeatureType
                InstallState = $Role.InstallState.ToString()
            })
        }
        Write-Log "Server roles installed: $($ServerRoles.Count)"
    } catch { Write-Log "Server roles query failed (may need RSAT): $_" "WARN" }

    # BITS job history
    $BITSJobs = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        $BITSEvents = Get-WinEvent -FilterHashtable @{
            LogName   = "Microsoft-Windows-Bits-Client/Operational"
            Id        = @(3, 4, 59, 60, 61)
            StartTime = $StartTime
        } -ErrorAction SilentlyContinue

        foreach ($E in $BITSEvents) {
            $BITSJobs.Add([PSCustomObject]@{
                TimeCreated = $E.TimeCreated.ToString("o")
                EventID     = $E.Id
                Message     = ($E.Message -replace '\r?\n',' ').Substring(0,[Math]::Min(300,$E.Message.Length))
            })
        }
        Write-Log "BITS events: $($BITSJobs.Count)"
    } catch { Write-Log "BITS events failed: $_" "WARN" }

    $ServerArtifacts = [PSCustomObject]@{
        Collected              = $true
        ScheduledTaskExecution = $TaskExecEvents
        WinRMRemoteSessions    = $WinRMEvents
        ServiceExecution       = $ServiceExecEvents
        InstalledServerRoles   = $ServerRoles
        BITSTransfers          = $BITSJobs
    }
    Write-Log "Server artifacts: Tasks=$($TaskExecEvents.Count) WinRM=$($WinRMEvents.Count) Services=$($ServiceExecEvents.Count)"
}

$Evidence = [PSCustomObject]@{
    ChainOfCustody  = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=(Get-Date).ToString("o"); ToolVersion="1.0"; IsServer=$IsServer; DaysBack=$DaysBack }
    ArtifactType    = "ExecutionHistory"
    OSMode          = if ($IsServer) { "Server - includes task/service/WinRM execution history" } else { "Workstation - includes Timeline and browser execution history" }
    OutputDirectory = $OutDir
    SRUM            = $SRUMInfo
    PSHistory       = $PSHistories
    WindowsTimeline = $TimelineDBs
    CMDRunHistory   = $CMDHistory
    ServerArtifacts = $ServerArtifacts
}

$Evidence | ConvertTo-Json -Depth 8 | Out-File -FilePath $JsonFile -Encoding UTF8
$Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=(Get-Date).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] SRUM/History collected | PS Histories: $($PSHistories.Count) | Timeline: $($TimelineDBs.Count)" -ForegroundColor Green
if ($IsServer) {
    Write-Host "[+] Server extras | Tasks: $($ServerArtifacts.ScheduledTaskExecution.Count) | WinRM: $($ServerArtifacts.WinRMRemoteSessions.Count) | Services: $($ServerArtifacts.ServiceExecution.Count)" -ForegroundColor Cyan
}
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed"
