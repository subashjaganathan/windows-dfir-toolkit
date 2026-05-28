#Requires -Version 5.1
<#
.SYNOPSIS
    Exports all critical Windows Event Log files as raw .evtx files.

.DESCRIPTION
    Copies raw .evtx files from all key Windows event log channels
    to the evidence directory. Raw files allow independent verification
    and re-analysis with any forensic tool (Hayabusa, EvtxECmd,
    ELK, Splunk, etc.). Includes log size and last write metadata.

.COMPATIBILITY
    Windows 10/11 / Server 2016+ : Full

.IR_PHASE
    Evidence Preservation / Investigation

.MITRE_ATTCK
    T1070.001 - Clear Windows Event Logs
    T1562.002 - Disable Windows Event Logging

.FORENSIC_SAFETY
    Read-only copy of event log files

.AUTHOR
    DFIR Toolkit

.VERSION
    1.0
#>

Set-StrictMode -Off
$ErrorActionPreference = "Continue"
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) { Write-Warning "[!] Administrator privileges recommended for full event log access." }

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
$OutDir    = "$BasePath\EventLogs_Raw_${Hostname}_${Timestamp}"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$LogFile   = "$BasePath\EventLogs_Raw_Execution.log"
$JsonFile  = "$BasePath\EventLogs_Raw_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "Raw EVTX export started | Case: $CaseNum"

# Priority event log channels to export
$TargetLogs = @(
    # Critical - always export
    @{ Name="Security";                                    Priority="Critical" }
    @{ Name="System";                                      Priority="Critical" }
    @{ Name="Application";                                 Priority="Critical" }
    @{ Name="Windows PowerShell";                          Priority="Critical" }
    # High
    @{ Name="Microsoft-Windows-PowerShell/Operational";    Priority="High" }
    @{ Name="Microsoft-Windows-TaskScheduler/Operational"; Priority="High" }
    @{ Name="Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"; Priority="High" }
    @{ Name="Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"; Priority="High" }
    @{ Name="Microsoft-Windows-WMI-Activity/Operational";  Priority="High" }
    @{ Name="Microsoft-Windows-Windows Defender/Operational"; Priority="High" }
    @{ Name="Microsoft-Windows-Sysmon/Operational";        Priority="High" }
    # Medium
    @{ Name="Microsoft-Windows-Bits-Client/Operational";   Priority="Medium" }
    @{ Name="Microsoft-Windows-AppLocker/EXE and DLL";     Priority="Medium" }
    @{ Name="Microsoft-Windows-AppLocker/MSI and Script";  Priority="Medium" }
    @{ Name="Microsoft-Windows-AppLocker/Packaged app-Execution"; Priority="Medium" }
    @{ Name="Microsoft-Windows-WinRM/Operational";         Priority="Medium" }
    @{ Name="Microsoft-Windows-WinRM/Analytic";            Priority="Medium" }
    @{ Name="Microsoft-Windows-DriverFrameworks-UserMode/Operational"; Priority="Medium" }
    @{ Name="Microsoft-Windows-PrintService/Operational";  Priority="Medium" }
    @{ Name="Microsoft-Windows-PrintService/Admin";        Priority="Medium" }
    @{ Name="Microsoft-Windows-NetworkProfile/Operational";Priority="Medium" }
    @{ Name="Microsoft-Windows-WLAN-AutoConfig/Operational"; Priority="Medium" }
    @{ Name="Microsoft-Windows-DNS-Client/Operational";    Priority="Medium" }
    @{ Name="Microsoft-Windows-Crypto-NCrypt/Operational"; Priority="Medium" }
    # Server specific
    @{ Name="DFS Replication";                             Priority="Server" }
    @{ Name="Directory Service";                           Priority="Server" }
    @{ Name="DNS Server";                                  Priority="Server" }
    @{ Name="File Replication Service";                    Priority="Server" }
    @{ Name="Microsoft-Windows-Hyper-V-Worker-Admin";      Priority="Server" }
)

$Results = [System.Collections.Generic.List[PSCustomObject]]::new()
$TotalSize = 0

# Get all event log file paths from registry
$LogPaths = @{}
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog" -Recurse -ErrorAction SilentlyContinue |
    ForEach-Object {
        $File = (Get-ItemProperty $_.PSPath -Name File -ErrorAction SilentlyContinue).File
        if ($File -and $File -match "\.evtx$") {
            $LogPaths[$_.PSPath -replace ".*EventLog\\","" -replace "\\","/"] = $File
        }
    }

# Also get from WMI for operational logs
Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.LogFilePath) {
        $LogPaths[$_.LogName] = $_.LogFilePath -replace "%SystemRoot%","$env:SystemRoot"
    }
}

Write-Host "[*] Exporting $($TargetLogs.Count) event log channels..." -ForegroundColor Cyan

foreach ($Target in $TargetLogs) {
    $LogName = $Target.Name
    $Priority= $Target.Priority

    # Find the file path
    $FilePath = $LogPaths[$LogName]
    if (-not $FilePath) {
        # Try direct path pattern
        $SafeName  = $LogName -replace "[/\\]","-" -replace " ","-"
        $FilePath  = "$env:SystemRoot\System32\winevt\Logs\$SafeName.evtx"
        if (-not (Test-Path $FilePath)) {
            $FilePath = ($FilePath -replace "winevt\\Logs","winevt/Logs")
        }
    }

    # Expand environment variables
    if ($FilePath) {
        $FilePath = [System.Environment]::ExpandEnvironmentVariables($FilePath)
    }

    $Result = [PSCustomObject]@{
        LogName      = $LogName
        Priority     = $Priority
        SourcePath   = $FilePath
        CopiedPath   = $null
        SizeBytes    = $null
        LastModified = $null
        RecordCount  = $null
        CopyStatus   = "NotAttempted"
        SHA256       = $null
    }

    if ($FilePath -and (Test-Path $FilePath -ErrorAction SilentlyContinue)) {
        $FileInfo = Get-Item $FilePath -ErrorAction SilentlyContinue
        $Result.SizeBytes    = $FileInfo.Length
        $Result.LastModified = $FileInfo.LastWriteTimeUtc.ToString("o")
        $TotalSize          += $FileInfo.Length

        # Get record count
        try {
            $LogInfo = Get-WinEvent -ListLog $LogName -ErrorAction SilentlyContinue
            $Result.RecordCount = $LogInfo.RecordCount
        } catch {}

        # Copy the file
        $SafeFileName = ($LogName -replace "[/\\:<>|?*]","-") + ".evtx"
        $DestPath = "$OutDir\${Priority}_$SafeFileName"

        try {
            # Use wevtutil as primary method - works on locked live log files
            $WevtArgs = "epl `"$LogName`" `"$DestPath`""
            $WevtProc = Start-Process -FilePath "wevtutil.exe" -ArgumentList $WevtArgs -Wait -PassThru -NoNewWindow -ErrorAction SilentlyContinue
            if ((Test-Path $DestPath) -and (Get-Item $DestPath).Length -gt 0) {
                $Result.CopiedPath = $DestPath
                $Result.CopyStatus = "Success"
                $Result.SHA256     = (Get-FileHash $DestPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                Write-Host "  [+] $LogName ($([math]::Round($FileInfo.Length/1KB))KB)" -ForegroundColor Green
            } else {
                # Fallback: direct file copy
                Copy-Item $FilePath $DestPath -Force -ErrorAction SilentlyContinue
                if (Test-Path $DestPath) {
                    $Result.CopiedPath = $DestPath
                    $Result.CopyStatus = "Success via copy"
                    $Result.SHA256     = (Get-FileHash $DestPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                } else {
                    $Result.CopyStatus = "Failed - could not export"
                    Write-Host "  [!] $LogName - export failed" -ForegroundColor Yellow
                }
            }
        } catch {
            $Result.CopyStatus = "Error: $_"
            Write-Log "Export failed for $LogName : $_" "WARN"
        }
    } else {
        $Result.CopyStatus = "NotFound - log not enabled or not applicable"
    }

    Write-Log "$LogName [$Priority]: $($Result.CopyStatus) | Size: $($Result.SizeBytes)"
    $Results.Add($Result)
}

# Export full list of ALL available logs with sizes
Write-Host "[*] Cataloging all available event logs..." -ForegroundColor Cyan
$AllLogs = @(Get-WinEvent -ListLog * -ErrorAction SilentlyContinue |
    Sort-Object RecordCount -Descending |
    ForEach-Object {
        [PSCustomObject]@{
            LogName      = $_.LogName
            Enabled      = $_.IsEnabled
            RecordCount  = $_.RecordCount
            MaxSizeMB    = [math]::Round($_.MaximumSizeInBytes/1MB,1)
            LogFilePath  = $_.LogFilePath
            LogType      = $_.LogType
        }
    })

$Successful = ($Results | Where-Object { $_.CopyStatus -match "^Success" }).Count
Write-Log "Exported: $Successful/$($Results.Count) logs | Total size: $([math]::Round($TotalSize/1MB,1))MB"

$Evidence = [PSCustomObject]@{
    ChainOfCustody  = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=(Get-Date).ToString("o"); ToolVersion="1.0" }
    ArtifactType    = "RawEventLogExport"
    OutputDirectory = $OutDir
    ExportedCount   = $Successful
    TotalSizeMB     = [math]::Round($TotalSize/1MB,1)
    ExportResults   = $Results
    AllAvailableLogs= $AllLogs
    ParseNote       = "Use EvtxECmd.exe (Eric Zimmerman) or Hayabusa for timeline analysis of .evtx files"
}

$Evidence | ConvertTo-Json -Depth 6 | Out-File -FilePath $JsonFile -Encoding UTF8
$Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=(Get-Date).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] EVTX export complete: $Successful/$($Results.Count) logs | $([math]::Round($TotalSize/1MB,1))MB" -ForegroundColor Green
Write-Host "[+] Output: $OutDir" -ForegroundColor Green
Write-Log "Completed"
