#Requires -Version 5.1
<#
.SYNOPSIS
    Collects $MFT, $UsnJrnl, and $LogFile filesystem metadata artifacts.

.DESCRIPTION
    Copies the Master File Table ($MFT), USN Change Journal ($UsnJrnl),
    and $LogFile from all NTFS volumes. These prove file existence even
    after deletion and provide a complete filesystem change history.
    Uses raw volume access via esentutl and RawCopy technique.

.COMPATIBILITY
    Windows 10/11 / Server 2016+ : Full (NTFS volumes only)

.IR_PHASE
    File System Forensics / Timeline Analysis

.MITRE_ATTCK
    T1070.004 - File Deletion
    T1565.001 - Stored Data Manipulation
    T1036     - Masquerading

.FORENSIC_SAFETY
    Read-only raw volume copy

.AUTHOR
    DFIR Toolkit

.VERSION
    1.0
#>

Set-StrictMode -Off
$ErrorActionPreference = "Continue"


# --- Shared toolkit module: single source of truth for version + base paths ---
$__DFIRMod = Join-Path $PSScriptRoot '..\Infrastructure\DFIR_Common.psm1'
if (Test-Path $__DFIRMod) { Import-Module $__DFIRMod -Force -ErrorAction SilentlyContinue }
if (-not $Global:DFIR_ToolVersion) { $Global:DFIR_ToolVersion = '1.0' }
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) { Write-Error "[!] Must run as Administrator."; exit 1 }

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
$OutDir    = "$BasePath\MFT_USN_${Hostname}_${Timestamp}"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$LogFile  = "$BasePath\MFT_USN_Execution.log"
$JsonFile = "$BasePath\MFT_USN_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "MFT/USN collection started | Case: $CaseNum"

$Results = [System.Collections.Generic.List[PSCustomObject]]::new()

# Get all NTFS volumes
$Volumes = @(Get-Volume -ErrorAction SilentlyContinue |
    Where-Object { $_.FileSystem -eq "NTFS" -and $_.DriveLetter })

Write-Host "[*] Found $($Volumes.Count) NTFS volumes: $(($Volumes.DriveLetter -join ', '))" -ForegroundColor Cyan
Write-Log "NTFS volumes: $(($Volumes.DriveLetter -join ', '))"

foreach ($Vol in $Volumes) {
    $Drive    = "$($Vol.DriveLetter):"
    $VolLabel = if ($Vol.FileSystemLabel) { $Vol.FileSystemLabel } else { "NoLabel" }
    $SafeName = "$($Vol.DriveLetter)_${VolLabel}"

    Write-Host "[*] Processing volume $Drive ($VolLabel)..." -ForegroundColor Cyan
    Write-Log "Processing volume: $Drive"

    $VolResult = [PSCustomObject]@{
        Drive           = $Drive
        Label           = $VolLabel
        SizeGB          = [math]::Round($Vol.Size / 1GB, 2)
        MFTCopied       = $false
        MFTPath         = $null
        MFTSizeBytes    = $null
        USNCopied       = $false
        USNPath         = $null
        LogFileCopied   = $false
        LogFilePath     = $null
        Error           = $null
    }

    # -- Copy $MFT -----------------------------------------------------------
    Write-Host "  [*] Copying `$MFT from $Drive..." -ForegroundColor Cyan
    $MFTDest = "$OutDir\${SafeName}_MFT"
    try {
        $MFTCopied = $false

        # Method 1: VSS shadow copy (most reliable without external tools)
        $VSSResult = (vssadmin list shadows /for=$Drive 2>&1) -join " "
        if ($VSSResult -match "Shadow Copy Volume Name:\s*(\S+)") {
            $ShadowPath = $Matches[1].TrimEnd("\")
            $MFTSource  = "${ShadowPath}\`$MFT"
            try {
                Copy-Item $MFTSource $MFTDest -Force -ErrorAction Stop
                $MFTCopied = $true
                $VolResult.MFTCopied    = $true
                $VolResult.MFTPath      = $MFTDest
                $VolResult.MFTSizeBytes = (Get-Item $MFTDest -ErrorAction SilentlyContinue).Length
                Write-Log "MFT copied via VSS: $Drive"
            } catch { Write-Log "VSS MFT copy failed: $_" "WARN" }
        }

        # Method 2: Raw volume read via .NET FileStream (no VSS needed)
        if (-not $MFTCopied) {
            try {
                $VolumePath = "\\.\" + $Drive.TrimEnd("\")
                $fs = [System.IO.File]::Open($VolumePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                # Read first 1KB to verify access
                $buf = New-Object byte[] 1024
                $read = $fs.Read($buf, 0, 1024)
                $fs.Close()
                if ($read -gt 0) {
                    # Use robocopy with /B flag (backup mode) to copy locked files
                    $RoboResult = robocopy "$Drive\" $OutDir "`$MFT" /B /NJH /NJS /NFL /NDL 2>&1
                    $RoboCopied = "$OutDir\`$MFT"
                    if (Test-Path $RoboCopied) {
                        Rename-Item $RoboCopied $MFTDest -Force -ErrorAction SilentlyContinue
                        if (Test-Path $MFTDest) {
                            $MFTCopied = $true
                            $VolResult.MFTCopied    = $true
                            $VolResult.MFTPath      = $MFTDest
                            $VolResult.MFTSizeBytes = (Get-Item $MFTDest).Length
                            Write-Log "MFT copied via robocopy /B: $Drive"
                        }
                    }
                }
            } catch { Write-Log "Raw volume MFT read failed: $_" "WARN" }
        }

        # Method 3: esentutl with /vss flag
        if (-not $MFTCopied) {
            try {
                $EsentResult = & esentutl /y "$Drive\`$MFT" /vss /d "$MFTDest" 2>&1
                if (Test-Path $MFTDest) {
                    $MFTCopied = $true
                    $VolResult.MFTCopied    = $true
                    $VolResult.MFTPath      = $MFTDest
                    $VolResult.MFTSizeBytes = (Get-Item $MFTDest).Length
                    Write-Log "MFT copied via esentutl: $Drive"
                }
            } catch { Write-Log "esentutl MFT copy failed: $_" "WARN" }
        }

        # Method 3: Record metadata + note for offline extraction
        if (-not $MFTCopied) {
            $MFTInfo = Get-Item "$Drive\`$MFT" -Force -ErrorAction SilentlyContinue
            $VolResult.MFTSizeBytes = if ($MFTInfo) { $MFTInfo.Length } else { $null }
            $VolResult.MFTPath      = "Metadata only - run MFTECmd.exe on mounted image offline"
            $VolResult.MFTNote      = "For full MFT extraction: MFTECmd.exe -f `$MFT --csv output"
            Write-Log "MFT metadata recorded for $Drive - offline extraction required"
        }
    } catch {
        $VolResult.Error = "MFT: $_"
        Write-Log "MFT collection failed for ${Drive}: $_" "WARN"
    }

    # -- Copy $UsnJrnl ---------------------------------------------------------
    Write-Host "  [*] Copying `$UsnJrnl from $Drive..." -ForegroundColor Cyan
    $USNDest = "$OutDir\${SafeName}_UsnJrnl"
    try {
        # Try VSS path first
        $VSSResult2 = (vssadmin list shadows /for=$Drive 2>&1) -join " "
        if ($VSSResult2 -match "Shadow Copy Volume Name:\s*(\S+)") {
            $ShadowPath2 = $Matches[1]
            $USNSource = "$ShadowPath2\`$Extend\`$UsnJrnl:`$J"
            if (Test-Path $USNSource -ErrorAction SilentlyContinue) {
                Copy-Item $USNSource $USNDest -Force -ErrorAction Stop
                $VolResult.USNCopied = $true
                $VolResult.USNPath   = $USNDest
                Write-Log "UsnJrnl copied via VSS: $Drive"
            }
        }

        if (-not $VolResult.USNCopied) {
            # Record USN journal metadata via fsutil
            $FSUtilOut = (fsutil usn queryjournal $Drive 2>&1) -join "`n"
            $USNMeta = [PSCustomObject]@{
                Drive          = $Drive
                FSUtilOutput   = $FSUtilOut
                JournalID      = if ($FSUtilOut -match "Journal ID\s*:\s*(\S+)") { $Matches[1] } else { $null }
                FirstUSN       = if ($FSUtilOut -match "First USN\s*:\s*(\S+)") { $Matches[1] } else { $null }
                NextUSN        = if ($FSUtilOut -match "Next USN\s*:\s*(\S+)") { $Matches[1] } else { $null }
                MaxSize        = if ($FSUtilOut -match "Maximum Size\s*:\s*(\S+)") { $Matches[1] } else { $null }
                Note           = "Use MFTECmd.exe -f UsnJrnl --csv for full parsing"
            }
            $USNMeta | ConvertTo-Json | Out-File "$OutDir\${SafeName}_UsnJrnl_metadata.json" -Encoding UTF8
            $VolResult.USNPath = "$OutDir\${SafeName}_UsnJrnl_metadata.json"
            Write-Log "UsnJrnl metadata recorded for $Drive"
        }
    } catch {
        Write-Log "UsnJrnl failed for $Drive : $_" "WARN"
    }

    # -- Copy $LogFile (NTFS transaction log) ----------------------------------
    Write-Host "  [*] Copying `$LogFile from $Drive..." -ForegroundColor Cyan
    $LogFileDest = "$OutDir\${SafeName}_LogFile"
    try {
        $VSSResult3 = (vssadmin list shadows /for=$Drive 2>&1) -join " "
        if ($VSSResult3 -match "Shadow Copy Volume Name:\s*(\S+)") {
            $ShadowPath3 = $Matches[1]
            $LogFileSource = "$ShadowPath3\`$LogFile"
            if (Test-Path $LogFileSource -ErrorAction SilentlyContinue) {
                Copy-Item $LogFileSource $LogFileDest -Force -ErrorAction Stop
                $VolResult.LogFileCopied = $true
                $VolResult.LogFilePath   = $LogFileDest
                Write-Log "LogFile copied via VSS: $Drive"
            }
        }
        if (-not $VolResult.LogFileCopied) {
            Write-Log "LogFile VSS not available for $Drive - use offline acquisition" "WARN"
        }
    } catch {
        Write-Log "LogFile failed for $Drive : $_" "WARN"
    }

    $Results.Add($VolResult)
}

# -- VSS Snapshot Inventory ----------------------------------------------------
Write-Host "[*] Enumerating all Volume Shadow Copies..." -ForegroundColor Cyan
$VSSAll = @(Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue | ForEach-Object {
    [PSCustomObject]@{
        ID             = $_.ID
        VolumeName     = $_.VolumeName
        DeviceName     = $_.DeviceObject
        CreationDate   = $_.InstallDate
        ClientAccessible = $_.ClientAccessible
        Count          = $_.Count
    }
})
Write-Log "VSS snapshots found: $($VSSAll.Count)"

# -- fsutil volume info --------------------------------------------------------
$VolumeInfo = @(Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.FileSystem -eq "NTFS" } | ForEach-Object {
    $Drive2 = "$($_.DriveLetter):"
    $FSInfo = (fsutil fsinfo ntfsinfo $Drive2 2>&1) -join "`n"
    [PSCustomObject]@{
        Drive          = $Drive2
        Label          = $_.FileSystemLabel
        TotalGB        = [math]::Round($_.Size/1GB,2)
        FreeGB         = [math]::Round($_.SizeRemaining/1GB,2)
        MFTRecordSize  = if ($FSInfo -match "Mft Record Size\s*:\s*(.+)") { $Matches[1].Trim() } else { $null }
        ClusterSize    = if ($FSInfo -match "Bytes Per Cluster\s*:\s*(.+)") { $Matches[1].Trim() } else { $null }
        SerialNumber   = if ($FSInfo -match "Volume Serial Number\s*:\s*(.+)") { $Matches[1].Trim() } else { $null }
    }
})

$Evidence = [PSCustomObject]@{
    ChainOfCustody = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=([DateTime]::UtcNow).ToString("o"); ToolVersion=$Global:DFIR_ToolVersion }
    ArtifactType   = "MFT_USNJournal_LogFile"
    OutputDirectory= $OutDir
    VolumeResults  = $Results
    ShadowCopies   = $VSSAll
    VolumeInfo     = $VolumeInfo
    ParseNote      = "Use MFTECmd.exe, MFTExplorer (Eric Zimmerman) for MFT parsing. Use MFTECmd.exe --usn for UsnJrnl."
}

$Evidence | ConvertTo-Json -Depth 7 | Out-File -FilePath $JsonFile -Encoding UTF8
$Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=([DateTime]::UtcNow).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

$MFTCount = ($Results | Where-Object { $_.MFTCopied }).Count
$USNCount = ($Results | Where-Object { $_.USNCopied }).Count
Write-Host "[+] MFT/USN collection complete | MFT: $MFTCount/$($Results.Count) | USN: $USNCount/$($Results.Count) | VSS: $($VSSAll.Count)" -ForegroundColor Green
Write-Host "[+] Output: $OutDir" -ForegroundColor Green
Write-Log "Completed"
