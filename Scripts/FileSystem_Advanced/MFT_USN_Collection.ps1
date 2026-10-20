#Requires -Version 5.1
<#
.SYNOPSIS
    Collects $MFT, $UsnJrnl:$J and $LogFile from every fixed NTFS volume.

.DESCRIPTION
    These NTFS metafiles prove file existence after deletion and give the
    complete change history ($J) and recent metadata transactions ($LogFile).

    They cannot be opened through normal file APIs - Copy-Item (even from a
    shadow copy), robocopy /B and esentutl all fail on them, which is why the
    previous version almost always fell back to "metadata only". This version
    takes a FRESH shadow copy of each volume (shared with Registry_Hive_Export,
    removed at the end of the run) and extracts the metafiles with raw cluster
    reads from the shadow device, following each file's own $DATA run list.

    The volume holding the evidence output itself is skipped.

.COMPATIBILITY
    Windows 10/11 / Server 2016+ : Full (NTFS volumes only)

.IR_PHASE
    File System Forensics / Timeline Analysis

.MITRE_ATTCK
    T1070.004 - File Deletion
    T1070.006 - Timestomp
    T1565.001 - Stored Data Manipulation
    T1036     - Masquerading

.FORENSIC_SAFETY
    Read-only raw reads from a shadow copy. Creating the shadow writes
    copy-on-write data to the volume; its ID is recorded and it is removed.

.AUTHOR
    DFIR Toolkit

.VERSION
    2.0
#>

Set-StrictMode -Off
$ErrorActionPreference = "Continue"

# --- Shared toolkit modules ---------------------------------------------------
$__DFIRMod = Join-Path $PSScriptRoot '..\Infrastructure\DFIR_Common.psm1'
if (Test-Path $__DFIRMod) { Import-Module $__DFIRMod -Force -ErrorAction SilentlyContinue }
if (-not $Global:DFIR_ToolVersion) { $Global:DFIR_ToolVersion = '1.1' }
Import-Module (Join-Path $PSScriptRoot '..\Infrastructure\DFIR_RawAcquisition.psm1') -Force -ErrorAction Stop

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
# throw (not exit): the orchestrator records a throw as Failed; an exit was recorded as "Success".
if (-not $IsAdmin) { throw "MFT_USN_Collection requires Administrator (raw volume reads, shadow copies)." }

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
$OutputDrive = ([IO.Path]::GetPathRoot((New-Object IO.DirectoryInfo $BasePath).FullName)).TrimEnd('\').ToUpperInvariant()

$Volumes = @(Get-Volume -ErrorAction SilentlyContinue |
    Where-Object { $_.FileSystem -eq "NTFS" -and $_.DriveLetter -and $_.DriveType -eq 'Fixed' })
Write-Host "[*] Fixed NTFS volumes: $(($Volumes.DriveLetter -join ', '))" -ForegroundColor Cyan
Write-Log "Fixed NTFS volumes: $(($Volumes.DriveLetter -join ', ')) | output volume: $OutputDrive"

function Get-Extracted($Path) {
    if (Test-Path -LiteralPath $Path) {
        $i = Get-Item -LiteralPath $Path
        return @{ Size = $i.Length; Hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }
    }
    $null
}

foreach ($Vol in $Volumes) {
    $Drive    = "$($Vol.DriveLetter):"
    $VolLabel = if ($Vol.FileSystemLabel) { $Vol.FileSystemLabel } else { "NoLabel" }
    $SafeName = "$($Vol.DriveLetter)_$($VolLabel -replace '[^\w.-]', '_')"
    $VolResult = [PSCustomObject]@{
        Drive = $Drive; Label = $VolLabel; SizeGB = [math]::Round($Vol.Size / 1GB, 2)
        ShadowId = $null
        MFTCopied = $false; MFTPath = $null; MFTSizeBytes = $null; MFTSHA256 = $null
        USNCopied = $false; USNPath = $null; USNSizeBytes = $null; USNSHA256 = $null
        LogFileCopied = $false; LogFilePath = $null; LogFileSizeBytes = $null; LogFileSHA256 = $null
        Method = $null; Error = $null
    }
    if ($Drive.ToUpperInvariant() -eq $OutputDrive) {
        $VolResult.Error = "skipped: this volume holds the evidence output"
        Write-Log "Skipping $Drive (evidence output volume)"
        $Results.Add($VolResult); continue
    }

    Write-Host "[*] $Drive ($VolLabel): shadow copy + raw NTFS read..." -ForegroundColor Cyan
    $Shadow = Get-DfirShadow -Volume $Drive -LogFile $LogFile
    if (-not $Shadow) {
        $VolResult.Error = "no shadow copy could be created - acquire `$MFT/`$J/`$LogFile from a disk image"
        Write-Log "No shadow for $Drive" "WARN"
        $Results.Add($VolResult); continue
    }
    $VolResult.ShadowId = $Shadow.Id
    $VolResult.Method   = "raw NTFS read from VSS shadow device"
    $Device = $Shadow.Device
    $errs = @()

    # $MFT (record 0) - also needed to locate $UsnJrnl
    $MFTDest = "$OutDir\${SafeName}_MFT"
    try {
        [DfirRawNtfs]::ExtractSystemFile($Device, 0, $MFTDest) | Out-Null
        $x = Get-Extracted $MFTDest
        if ($x) { $VolResult.MFTCopied = $true; $VolResult.MFTPath = $MFTDest; $VolResult.MFTSizeBytes = $x.Size; $VolResult.MFTSHA256 = $x.Hash }
        Write-Log "$Drive `$MFT: $($x.Size) bytes"
    } catch { $errs += "MFT: $($_.Exception.GetBaseException().Message)"; Write-Log "$Drive `$MFT failed: $_" "WARN" }

    # $LogFile (record 2)
    $LogDest = "$OutDir\${SafeName}_LogFile"
    try {
        [DfirRawNtfs]::ExtractSystemFile($Device, 2, $LogDest) | Out-Null
        $x = Get-Extracted $LogDest
        if ($x) { $VolResult.LogFileCopied = $true; $VolResult.LogFilePath = $LogDest; $VolResult.LogFileSizeBytes = $x.Size; $VolResult.LogFileSHA256 = $x.Hash }
        Write-Log "$Drive `$LogFile: $($x.Size) bytes"
    } catch { $errs += "LogFile: $($_.Exception.GetBaseException().Message)"; Write-Log "$Drive `$LogFile failed: $_" "WARN" }

    # $UsnJrnl:$J (located through the extracted $MFT; sparse prefix skipped)
    if ($VolResult.MFTCopied) {
        $USNDest = "$OutDir\${SafeName}_UsnJrnl_J"
        try {
            $w = [DfirRawNtfs]::ExtractUsnJournal($Device, $MFTDest, $USNDest)
            if ($w -ge 0) {
                $x = Get-Extracted $USNDest
                if ($x) { $VolResult.USNCopied = $true; $VolResult.USNPath = $USNDest; $VolResult.USNSizeBytes = $x.Size; $VolResult.USNSHA256 = $x.Hash }
                Write-Log "$Drive `$UsnJrnl:`$J: $($x.Size) bytes (sparse prefix skipped)"
            } else { $errs += "USN: journal not found (disabled on this volume?)" }
        } catch { $errs += "USN: $($_.Exception.GetBaseException().Message)"; Write-Log "$Drive `$J failed: $_" "WARN" }
    }
    # Journal metadata (first/next USN) for context, regardless of extraction
    try {
        $FSUtilOut = (fsutil usn queryjournal $Drive 2>&1) -join "`n"
        $VolResult | Add-Member -NotePropertyName UsnJournalInfo -NotePropertyValue ([PSCustomObject]@{
            JournalID = if ($FSUtilOut -match "Journal ID\s*:\s*(\S+)") { $Matches[1] } else { $null }
            FirstUSN  = if ($FSUtilOut -match "First USN\s*:\s*(\S+)") { $Matches[1] } else { $null }
            NextUSN   = if ($FSUtilOut -match "Next USN\s*:\s*(\S+)") { $Matches[1] } else { $null }
            MaxSize   = if ($FSUtilOut -match "Maximum Size\s*:\s*(\S+)") { $Matches[1] } else { $null }
        })
    } catch {}
    if ($errs) { $VolResult.Error = $errs -join '; ' }
    Write-Host ("  [+] MFT {0} | LogFile {1} | UsnJrnl {2}" -f $VolResult.MFTCopied, $VolResult.LogFileCopied, $VolResult.USNCopied) -ForegroundColor Green
    $Results.Add($VolResult)
}

# Standalone run: remove the shadows we created (the orchestrator removes them at the end of the run).
if (-not $env:DFIR_ORCHESTRATED) { Remove-DfirShadows -LogFile $LogFile }

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

$MFTCount = @($Results | Where-Object { $_.MFTCopied }).Count
$USNCount = @($Results | Where-Object { $_.USNCopied }).Count
Write-Host "[+] MFT/USN collection complete | MFT: $MFTCount/$($Results.Count) | USN: $USNCount/$($Results.Count) | VSS: $($VSSAll.Count)" -ForegroundColor Green
Write-Host "[+] Output: $OutDir" -ForegroundColor Green
Write-Log "Completed"
