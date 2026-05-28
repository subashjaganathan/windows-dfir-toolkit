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
try {
    $SBEvents = Get-WinEvent -FilterHashtable @{
        LogName   = "Microsoft-Windows-PowerShell/Operational"
        Id        = 4104
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue

    foreach ($Evt in $SBEvents) {
        $Msg = $Evt.Message
        $ScriptBlocks.Add([PSCustomObject]@{
            TimeCreated     = $Evt.TimeCreated.ToString("o")
            EventID         = 4104
            Computer        = $Evt.MachineName
            UserSID         = $Evt.UserId
            ScriptText      = $(if ($Msg.Length -gt 2000) { $Msg.Substring(0,2000) + "...[TRUNCATED]" } else { $Msg })
            FullLength      = $Msg.Length
            IsSuspicious    = ($Msg -match "IEX|Invoke-Expression|FromBase64|EncodedCommand|-enc|-e |bypass|DownloadString|WebClient|hidden|noprofile|Reflection\.Assembly|shellcode|mimikatz|sekurlsa|lsadump|empire|cobalt" )
            RecordID        = $Evt.RecordId
        })
    }
    Write-Log "Script block events: $($ScriptBlocks.Count)"
} catch { Write-Log "ERROR collecting script block events: $_" "ERROR" }

# -- Module Logging (4103) ------------------------------------------------------
Write-Host "[*] Collecting PowerShell Module events (4103)..." -ForegroundColor Cyan
$ModuleEvents = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $MEvents = Get-WinEvent -FilterHashtable @{
        LogName   = "Microsoft-Windows-PowerShell/Operational"
        Id        = 4103
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue | Select-Object -First 1000  # cap at 1000

    foreach ($Evt in $MEvents) {
        $ModuleEvents.Add([PSCustomObject]@{
            TimeCreated = $Evt.TimeCreated.ToString("o")
            EventID     = 4103
            Computer    = $Evt.MachineName
            Message     = ($Evt.Message -replace '\r?\n',' ').Substring(0,[Math]::Min(500,$Evt.Message.Length))
            RecordID    = $Evt.RecordId
        })
    }
    Write-Log "Module log events: $($ModuleEvents.Count)"
} catch { Write-Log "ERROR collecting module events: $_" "ERROR" }

# -- Windows PowerShell legacy log ---------------------------------------------
Write-Host "[*] Collecting Windows PowerShell legacy events (400/403/600)..." -ForegroundColor Cyan
$LegacyEvents = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $LEv = Get-WinEvent -FilterHashtable @{
        LogName   = "Windows PowerShell"
        Id        = @(400, 403, 600)
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue

    foreach ($Evt in $LEv) {
        $LegacyEvents.Add([PSCustomObject]@{
            TimeCreated = $Evt.TimeCreated.ToString("o")
            EventID     = $Evt.Id
            Level       = $Evt.LevelDisplayName
            Message     = ($Evt.Message -replace '\r?\n',' ').Substring(0,[Math]::Min(500,$Evt.Message.Length))
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
        $Lines = Get-Content $HistPath -ErrorAction SilentlyContinue
        $HistoryFiles.Add([PSCustomObject]@{
            UserProfile = $_.Name
            FilePath    = $HistPath
            LineCount   = $Lines.Count
            Commands    = $Lines
        })
    }
}
Write-Log "PS history files found: $($HistoryFiles.Count)"

$SuspiciousCount = ($ScriptBlocks | Where-Object { $_.IsSuspicious }).Count

$Evidence = [PSCustomObject]@{
    ChainOfCustody = [PSCustomObject]@{
        CaseNumber  = $CaseNum; Hostname = $Hostname
        CollectedAt = (Get-Date).ToString("o"); ToolVersion="1.0"; DaysBack = $DaysBack
    }
    ArtifactType        = "PowerShellEventLog"
    LoggingConfig       = $PSConfig
    SuspiciousCount     = $SuspiciousCount
    ScriptBlockEvents   = $ScriptBlocks
    ModuleLogEvents     = $ModuleEvents
    LegacyEvents        = $LegacyEvents
    PSHistoryFiles      = $HistoryFiles
}

$Evidence | ConvertTo-Json -Depth 8 | Out-File -FilePath $JsonFile -Encoding UTF8
$Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=(Get-Date).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] PowerShell logs collected | ScriptBlocks: $($ScriptBlocks.Count) | Suspicious: $SuspiciousCount" -ForegroundColor Green
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed"
