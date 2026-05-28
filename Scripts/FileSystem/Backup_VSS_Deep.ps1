#Requires -Version 5.1
Set-StrictMode -Off
$ErrorActionPreference = "Continue"
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
$LogFile  = "$BasePath\Backup_VSS_Execution.log"
$JsonFile = "$BasePath\Backup_VSS_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "Backup/VSS deep collection started | Case: $CaseNum"

# VSS Shadow Copy inventory
Write-Host "[*] Enumerating Volume Shadow Copies..." -ForegroundColor Cyan
$ShadowCopies = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $VSS = @(Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue)
    foreach ($S in $VSS) {
        $ShadowCopies.Add([PSCustomObject]@{
            ID               = $S.ID
            VolumeName       = $S.VolumeName
            DeviceObject     = $S.DeviceObject
            CreationDate     = $S.InstallDate.ToString("o")
            ClientAccessible = $S.ClientAccessible
            Persistent       = $S.Persistent
            State            = $S.State
            Count            = $S.Count
        })
    }
    Write-Log "Shadow copies found: $($ShadowCopies.Count)"
} catch { Write-Log "VSS query failed: $_" "WARN" }

# vssadmin output
Write-Host "[*] Running vssadmin inventory..." -ForegroundColor Cyan
$VSSAdminOut = [PSCustomObject]@{ ListShadows = ""; ListProviders = ""; ListWriters = "" }
try {
    $VSSAdminOut = [PSCustomObject]@{
        ListShadows   = (vssadmin list shadows 2>&1) -join "`n"
        ListProviders = (vssadmin list providers 2>&1) -join "`n"
        ListWriters   = (vssadmin list writers 2>&1) -join "`n"
    }
} catch { Write-Log "vssadmin failed: $_" "WARN" }

# VSS deletion events - ransomware indicator
Write-Host "[*] Checking for VSS deletion events (ransomware indicator)..." -ForegroundColor Cyan
$VSSDeletionEvents = [System.Collections.Generic.List[PSCustomObject]]::new()
$DaysBack = if ($env:DFIR_DAYS) { [int]$env:DFIR_DAYS } else { 30 }
$SinceDate = (Get-Date).AddDays(-$DaysBack)
try {
    $Filter = @{
        LogName   = "System"
        Id        = @(8193, 8194, 8197, 8199)
        StartTime = $SinceDate
    }
    $VSSEvents = @(Get-WinEvent -FilterHashtable $Filter -ErrorAction SilentlyContinue)
    foreach ($E in $VSSEvents) {
        $VSSDeletionEvents.Add([PSCustomObject]@{
            TimeCreated = $E.TimeCreated.ToString("o")
            EventID     = $E.Id
            Message     = $E.Message -replace "\r?\n"," "
            Computer    = $E.MachineName
        })
    }
    Write-Log "VSS deletion/failure events: $($VSSDeletionEvents.Count)"
} catch { Write-Log "VSS event query failed: $_" "WARN" }

# Command-line VSS deletion evidence
Write-Host "[*] Checking Security log for VSS deletion commands..." -ForegroundColor Cyan
$VSSDeletionCmds = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $CmdFilter = @{
        LogName   = "Security"
        Id        = 4688
        StartTime = $SinceDate
    }
    $CmdEvents = @(Get-WinEvent -FilterHashtable $CmdFilter -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match "vssadmin.*delete|wmic.*shadowcopy.*delete|wbadmin.*delete|bcdedit.*recoveryenabled" })
    foreach ($E in $CmdEvents) {
        $VSSDeletionCmds.Add([PSCustomObject]@{
            TimeCreated  = $E.TimeCreated.ToString("o")
            EventID      = $E.Id
            CommandLine  = if ($E.Message -match "Process Command Line:\s*(.+?)(\r|\n|$)") { $Matches[1].Trim() } else { $null }
            SubjectUser  = if ($E.Message -match "Subject:\s*.*?Account Name:\s*(\S+)") { $Matches[1] } else { $null }
        })
    }
    Write-Log "VSS deletion commands in security log: $($VSSDeletionCmds.Count)"
} catch { Write-Log "VSS command search failed: $_" "WARN" }

# Windows Backup history
Write-Host "[*] Collecting Windows Backup history..." -ForegroundColor Cyan
$BackupHistory = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $BackupFilter = @{
        LogName   = "Microsoft-Windows-Backup"
        StartTime = $SinceDate
    }
    $BackupEvents = @(Get-WinEvent -FilterHashtable $BackupFilter -ErrorAction SilentlyContinue)
    foreach ($E in $BackupEvents) {
        $BackupHistory.Add([PSCustomObject]@{
            TimeCreated = $E.TimeCreated.ToString("o")
            EventID     = $E.Id
            Level       = $E.LevelDisplayName
            Message     = ($E.Message -replace "\r?\n"," ").Substring(0,[Math]::Min(200,$E.Message.Length))
        })
    }
    Write-Log "Backup events: $($BackupHistory.Count)"
} catch { Write-Log "Backup log not available: $_" "WARN" }

# Windows Backup service state
$WBService = Get-Service wbengine -ErrorAction SilentlyContinue
$BackupServiceState = if ($WBService) { $WBService.Status.ToString() } else { "Not installed" }

# File History state
Write-Host "[*] Checking File History state..." -ForegroundColor Cyan
$FileHistory = [PSCustomObject]@{ Enabled = $false }
try {
    $FHKey = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SPP\Clients" -ErrorAction SilentlyContinue
    $FHService = Get-Service fhsvc -ErrorAction SilentlyContinue
    $FileHistory = [PSCustomObject]@{
        ServiceStatus = if ($FHService) { $FHService.Status.ToString() } else { "Not installed" }
        LastRun       = $null
    }
} catch {}

# Recycle Bin deep - per drive
Write-Host "[*] Collecting Recycle Bin metadata per drive..." -ForegroundColor Cyan
$RecycleBinData = [System.Collections.Generic.List[PSCustomObject]]::new()
Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue | ForEach-Object {
    $RBPath = $_.Root + '$Recycle.Bin'
    if (-not (Test-Path $RBPath -ErrorAction SilentlyContinue)) { return }
    Get-ChildItem $RBPath -Force -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match "^\`$I" } | ForEach-Object {
            $RecycleBinData.Add([PSCustomObject]@{
                Drive        = $_.PSDrive.ToString()
                MetaFile     = $_.Name
                FullPath     = $_.FullName
                SizeBytes    = $_.Length
                DeletedTime  = $_.LastWriteTimeUtc.ToString("o")
                Note         = "Pair with matching R file. Use RBCmd.exe for full parsing."
            })
        }
}
Write-Log "VSS: $($ShadowCopies.Count) | VSS deletions: $($VSSDeletionCmds.Count) | Backup events: $($BackupHistory.Count) | RecycleBin: $($RecycleBinData.Count)"

$RansomwareIndicators = $VSSDeletionCmds.Count -gt 0 -or $VSSDeletionEvents.Count -gt 0

$Evidence = [PSCustomObject]@{
    ChainOfCustody          = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=(Get-Date).ToString("o"); ToolVersion="1.0" }
    ArtifactType            = "Backup_VSS_Deep"
    ShadowCopyCount         = $ShadowCopies.Count
    VSSDeletionEventCount   = $VSSDeletionEvents.Count
    VSSDeletionCmdCount     = $VSSDeletionCmds.Count
    RansomwareIndicators    = $RansomwareIndicators
    BackupServiceState      = $BackupServiceState
    ShadowCopies            = $ShadowCopies
    VSSAdminOutput          = $VSSAdminOut
    VSSDeletionEvents       = $VSSDeletionEvents
    VSSDeletionCommands     = $VSSDeletionCmds
    BackupHistory           = $BackupHistory
    FileHistory             = $FileHistory
    RecycleBin              = $RecycleBinData
}

$Evidence | ConvertTo-Json -Depth 6 | Out-File $JsonFile -Encoding UTF8
$Hash = Get-FileHash $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=(Get-Date).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

$RiskMsg = if ($RansomwareIndicators) { "RANSOMWARE INDICATORS DETECTED" } else { "No ransomware indicators" }
Write-Host "[+] Backup/VSS deep complete | Shadows: $($ShadowCopies.Count) | VSS Deletions: $($VSSDeletionCmds.Count) | $RiskMsg" -ForegroundColor $(if($RansomwareIndicators){"Red"}else{"Green"})
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed | RansomwareIndicators: $RansomwareIndicators"
