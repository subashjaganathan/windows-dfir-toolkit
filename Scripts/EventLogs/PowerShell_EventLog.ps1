#Requires -Version 5.1
<#
.SYNOPSIS
    Collects PowerShell script block, module, and operational logs.

.DESCRIPTION
    Extracts PowerShell logging artifacts including script block
    logging (4104), module logging (4103), and transcription events.
    Critical for detecting living-off-the-land attacks and obfuscated
    PowerShell execution.

.IR_PHASE
    Execution / Investigation

.MITRE_ATTCK
    T1059.001 - PowerShell
    T1027     - Obfuscated Files
    T1140     - Deobfuscate/Decode

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
if (-not $IsAdmin) { Write-Warning "[!] Administrator privileges recommended." }

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
$LogFile  = "$BasePath\PS_EventLog_Execution.log"
$JsonFile = "$BasePath\PowerShell_EventLog_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "PowerShell event log collection started"

$DaysBack  = if ($env:DFIR_DAYS) { [int]$env:DFIR_DAYS } else { 30 }
$StartTime = (Get-Date).AddDays(-$DaysBack)

# -- Script Block Logging (4104) ------------------------------------------------
Write-Host "[*] Collecting PowerShell Script Block events (4104)..." -ForegroundColor Cyan

$ScriptBlocks = [System.Collections.Generic.List[PSCustomObject]]::new()
$MaxSB = 2000   # hard cap on events processed
$KeptSB = 0
try {
    # STREAM events one at a time instead of materializing all into memory.
    # Get-WinEvent piped to ForEach-Object processes lazily and lets each
    # event be garbage-collected, preventing OutOfMemory on heavily-logged hosts.
    Get-WinEvent -FilterHashtable @{
        LogName   = "Microsoft-Windows-PowerShell/Operational"
        Id        = 4104
        StartTime = $StartTime
    } -MaxEvents $MaxSB -ErrorAction SilentlyContinue | ForEach-Object {
        $Evt = $_
        $Msg = if ($Evt.Message) { $Evt.Message } else { "" }
        $MsgLen = $Msg.Length
        $IsSusp = ($Msg -match "IEX|Invoke-Expression|FromBase64|EncodedCommand|-enc|-e |bypass|DownloadString|WebClient|hidden|noprofile|Reflection\.Assembly|shellcode|mimikatz|sekurlsa|lsadump|empire|cobalt")
        # Keep short snippet for suspicious; almost nothing for benign (full text is in raw EVTX export anyway)
        $StoredText = if ($IsSusp) {
            if ($MsgLen -gt 1000) { $Msg.Substring(0,1000) + "...[TRUNCATED]" } else { $Msg }
        } else {
            if ($MsgLen -gt 120) { $Msg.Substring(0,120) + "...[TRUNCATED]" } else { $Msg }
        }
        $ScriptBlocks.Add([PSCustomObject]@{
            TimeCreated     = $Evt.TimeCreated.ToString("o")
            EventID         = 4104
            Computer        = $Evt.MachineName
            UserSID         = "$($Evt.UserId)"
            ScriptText      = $StoredText
            FullLength      = $MsgLen
            IsSuspicious    = $IsSusp
            RecordID        = $Evt.RecordId
        })
        $script:KeptSB++
    }
    Write-Log "Script block events: $($ScriptBlocks.Count) (capped at $MaxSB)"
    Write-Host "[*] Note: full script text preserved in raw EVTX export (PowerShell/Operational)" -ForegroundColor DarkGray
} catch {
    Write-Log "ERROR collecting script block events: $_" "ERROR"
    Write-Host "[!] Script block collection hit a limit; partial data kept ($($ScriptBlocks.Count) events)" -ForegroundColor Yellow
}

# -- Module Logging (4103) ------------------------------------------------------
Write-Host "[*] Collecting PowerShell Module events (4103)..." -ForegroundColor Cyan
$ModuleEvents = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $MEvents = Get-WinEvent -MaxEvents 1500 -FilterHashtable @{
        LogName   = "Microsoft-Windows-PowerShell/Operational"
        Id        = 4103
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue | Select-Object -First 1000  # cap at 1000

    foreach ($Evt in $MEvents) {
        $ModuleEvents.Add([PSCustomObject]@{
            TimeCreated = $Evt.TimeCreated.ToString("o")
            EventID     = 4103
            Computer    = $Evt.MachineName
            Message     = ($Evt.Message -split "`r?`n" -join " ").Substring(0,[Math]::Min(500,$Evt.Message.Length))
            RecordID    = $Evt.RecordId
        })
    }
    Write-Log "Module log events: $($ModuleEvents.Count)"
} catch { Write-Log "ERROR collecting module events: $_" "ERROR" }

# -- Windows PowerShell legacy log ---------------------------------------------
Write-Host "[*] Collecting Windows PowerShell legacy events (400/403/600)..." -ForegroundColor Cyan
$LegacyEvents = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $LEv = Get-WinEvent -MaxEvents 1500 -FilterHashtable @{
        LogName   = "Windows PowerShell"
        Id        = @(400, 403, 600)
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue

    foreach ($Evt in $LEv) {
        $LegacyEvents.Add([PSCustomObject]@{
            TimeCreated = $Evt.TimeCreated.ToString("o")
            EventID     = $Evt.Id
            Level       = $Evt.LevelDisplayName
            Message     = ($Evt.Message -split "`r?`n" -join " ").Substring(0,[Math]::Min(500,$Evt.Message.Length))
            RecordID    = $Evt.RecordId
        })
    }
    Write-Log "Legacy PS events: $($LegacyEvents.Count)"
} catch { Write-Log "ERROR collecting legacy PS events: $_" "ERROR" }

# -- PS Logging Config Check ----------------------------------------------------
$PSConfig = [PSCustomObject]@{
    ScriptBlockLoggingEnabled  = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging
    ModuleLoggingEnabled       = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ErrorAction SilentlyContinue).EnableModuleLogging
    TranscriptionEnabled       = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -ErrorAction SilentlyContinue).EnableTranscripting
    TranscriptionOutputDir     = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -ErrorAction SilentlyContinue).OutputDirectory
    ConstrainedLanguageMode    = $ExecutionContext.SessionState.LanguageMode
}

# -- PS History files -----------------------------------------------------------
$HistoryFiles = [System.Collections.Generic.List[PSCustomObject]]::new()
Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $HistPath = "$($_.FullName)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $HistPath) {
        $Lines = @(Get-Content $HistPath -ErrorAction SilentlyContinue -TotalCount 5000)
        $HistoryFiles.Add([PSCustomObject]@{
            UserProfile = $_.Name
            FilePath    = $HistPath
            LineCount   = $Lines.Count
            Commands    = @($Lines | Select-Object -Last 500)
        })
        $Lines = $null
    }
}
Write-Log "PS history files found: $($HistoryFiles.Count)"

$SuspiciousCount = ($ScriptBlocks | Where-Object { $_.IsSuspicious }).Count

$Evidence = [PSCustomObject]@{
    ChainOfCustody = [PSCustomObject]@{
        CaseNumber  = $CaseNum; Hostname = $Hostname
        CollectedAt = ([DateTime]::UtcNow).ToString("o"); ToolVersion=$Global:DFIR_ToolVersion; DaysBack = $DaysBack
    }
    ArtifactType        = "PowerShellEventLog"
    LoggingConfig       = $PSConfig
    SuspiciousCount     = $SuspiciousCount
    ScriptBlockEvents   = $ScriptBlocks
    ModuleLogEvents     = $ModuleEvents
    LegacyEvents        = $LegacyEvents
    PSHistoryFiles      = $HistoryFiles
}

try {
    $Evidence | ConvertTo-Json -Depth 5 -Compress | Out-File -FilePath $JsonFile -Encoding UTF8
} catch {
    Write-Log "Full JSON serialization failed ($_); writing reduced dataset" "WARN"
    Write-Host "[!] Dataset large - writing reduced JSON (suspicious events prioritized)" -ForegroundColor Yellow
    # Fallback: keep only suspicious script blocks + counts to guarantee output
    $Reduced = [PSCustomObject]@{
        ChainOfCustody    = $Evidence.ChainOfCustody
        ArtifactType      = "PowerShellEventLog"
        LoggingConfig     = $PSConfig
        SuspiciousCount   = $SuspiciousCount
        ScriptBlockEvents = @($ScriptBlocks | Where-Object { $_.IsSuspicious })
        ModuleLogEvents   = @($ModuleEvents | Select-Object -First 200)
        LegacyEvents      = @($LegacyEvents | Select-Object -First 200)
        Note              = "Reduced output due to volume; full script text in raw EVTX export"
    }
    $Reduced | ConvertTo-Json -Depth 5 -Compress | Out-File -FilePath $JsonFile -Encoding UTF8
}
$Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=([DateTime]::UtcNow).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] PowerShell logs collected | ScriptBlocks: $($ScriptBlocks.Count) | Suspicious: $SuspiciousCount" -ForegroundColor Green
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed"
