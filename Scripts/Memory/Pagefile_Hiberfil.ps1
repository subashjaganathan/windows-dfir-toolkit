#Requires -Version 5.1
<#
.SYNOPSIS
    Documents (and optionally captures) pagefile.sys, hiberfil.sys and swapfile.sys.

.DESCRIPTION
    These files hold paged-out memory and, for hiberfil.sys, a full compressed image of RAM.
    They are standard memory-forensics artifacts and a critical FALLBACK when a live RAM
    acquisition (WinPmem) is not possible (locked driver, incompatible host, Secure Boot / DSE).

    By default this script records CONFIGURATION and METADATA only (locations, sizes, whether
    the pagefile is cleared at shutdown, whether hibernation is enabled). The raw files are
    multi-gigabyte and locked while Windows runs, so RAW CAPTURE is OPT-IN:

        $env:DFIR_COPY_PAGEFILE = "1"     # copy pagefile/swapfile/hiberfil via VSS shadow copy

    When enabled it uses a VSS shadow copy (the live files are locked by the memory manager),
    SHA256-hashes each captured file, and records everything in a chain-of-custody manifest.

.COMPATIBILITY
    Windows 10/11 / Server 2016+ : Full

.IR_PHASE
    Live Response / Memory Forensics (fallback)

.MITRE_ATTCK
    T1003 - OS Credential Dumping (secrets recoverable from paged memory)
    T1059 - Command Execution (fileless artifacts paged to disk)

.FORENSIC_SAFETY
    Read-only. Metadata by default; raw copy (opt-in) reads from a VSS snapshot, never the live
    file, and never modifies the source.

.AUTHOR
    Subash J

.VERSION
    1.1
#>

Set-StrictMode -Off
$ErrorActionPreference = "Continue"

# --- Shared toolkit module: single source of truth for version + base paths ---
$__DFIRMod = Join-Path $PSScriptRoot '..\Infrastructure\DFIR_Common.psm1'
if (Test-Path $__DFIRMod) { Import-Module $__DFIRMod -Force -ErrorAction SilentlyContinue }
if (-not $Global:DFIR_ToolVersion) { $Global:DFIR_ToolVersion = '1.0' }
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
$LogFile   = "$BasePath\Pagefile_Hiberfil_Execution.log"
$JsonFile  = "$BasePath\Pagefile_Hiberfil_${Hostname}_${Timestamp}.json"
$OutDir    = "$BasePath\Pagefile_Hiberfil_${Hostname}_${Timestamp}"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "Pagefile/Hiberfil documentation started | Case: $CaseNum"

$DoCopy = ($env:DFIR_COPY_PAGEFILE -eq "1")
Write-Host "[*] Documenting pagefile / hiberfil / swapfile (raw copy: $DoCopy)..." -ForegroundColor Cyan

# -- Configuration ---------------------------------------------------------------
$PageFileSettings = @(Get-CimInstance Win32_PageFileSetting -ErrorAction SilentlyContinue |
    ForEach-Object { [PSCustomObject]@{ Name=$_.Name; InitialSizeMB=$_.InitialSize; MaximumSizeMB=$_.MaximumSize } })
$PageFileUsage = @(Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue |
    ForEach-Object { [PSCustomObject]@{ Name=$_.Name; AllocatedBaseSizeMB=$_.AllocatedBaseSize; CurrentUsageMB=$_.CurrentUsage; PeakUsageMB=$_.PeakUsage } })

$MMKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
$ClearAtShutdown = $null; $PagingFilesReg = $null
try {
    $mm = Get-ItemProperty $MMKey -ErrorAction SilentlyContinue
    $ClearAtShutdown = $mm.ClearPageFileAtShutdown
    $PagingFilesReg  = $mm.PagingFiles
} catch { Write-Log "Could not read MemoryManagement key: $_" "WARN" }

# Hibernation state (fsutil / power config)
$HibernateEnabled = $null
try {
    $HibKey = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -ErrorAction SilentlyContinue
    $HibernateEnabled = [bool]$HibKey.HibernateEnabled
} catch {}

# -- Per-file metadata (files are hidden/system/locked; enumerate defensively) ---
function Get-VolatileFileMeta {
    param([string]$Path)
    $meta = [PSCustomObject]@{ Path=$Path; Exists=$false; SizeBytes=$null; SizeGB=$null; LastWriteUTC=$null; CreationUTC=$null; Note="" }
    try {
        $fi = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        $meta.Exists       = $true
        $meta.SizeBytes    = $fi.Length
        $meta.SizeGB       = [math]::Round($fi.Length/1GB,2)
        $meta.LastWriteUTC = $fi.LastWriteTimeUtc.ToString("o")
        $meta.CreationUTC  = $fi.CreationTimeUtc.ToString("o")
    } catch {
        # Locked/!accessible: fall back to fsutil for the on-disk size where possible.
        $meta.Note = "Locked or inaccessible via Get-Item (expected for in-use files)."
        try {
            $fsu = (fsutil file queryextents "$Path" 2>&1) -join " "
            if ($fsu -notmatch "Error") { $meta.Exists = $true; $meta.Note += " On-disk extents present." }
        } catch {}
    }
    return $meta
}

$SystemDrive = $env:SystemDrive
$Targets = @(
    "$SystemDrive\pagefile.sys",
    "$SystemDrive\swapfile.sys",
    "$SystemDrive\hiberfil.sys"
)
$FileMeta = @($Targets | ForEach-Object { Get-VolatileFileMeta $_ })

# -- Optional raw capture via VSS -----------------------------------------------
$Captured = [System.Collections.Generic.List[PSCustomObject]]::new()
if ($DoCopy) {
    if (-not $IsAdmin) {
        Write-Warning "[!] Raw capture requires Administrator - skipping copy, metadata only."
        Write-Log "Raw copy requested but not admin - metadata only" "WARN"
    } else {
        New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
        # Create a fresh shadow copy of the system volume so we read a consistent, unlocked image.
        $ShadowPath = $null
        try {
            $shadow = (Get-CimInstance -ClassName Win32_ShadowCopy -ErrorAction SilentlyContinue |
                Sort-Object InstallDate -Descending | Select-Object -First 1)
            $create = Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{ Volume = "$SystemDrive\"; Context = "ClientAccessible" } -ErrorAction SilentlyContinue
            if ($create -and $create.ShadowID) {
                $new = Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue | Where-Object { $_.ID -eq $create.ShadowID }
                if ($new) { $ShadowPath = $new.DeviceObject }
            }
            if (-not $ShadowPath) {
                # Fall back to any existing shadow (vssadmin output parse)
                $vss = (vssadmin list shadows /for=$SystemDrive 2>&1) -join " "
                if ($vss -match "Shadow Copy Volume Name:\s*(\S+)") { $ShadowPath = $Matches[1] }
            }
        } catch { Write-Log "Shadow copy creation failed: $_" "WARN" }

        if ($ShadowPath) {
            $ShadowPath = $ShadowPath.TrimEnd('\')
            Write-Log "Using shadow: $ShadowPath"
            foreach ($t in $Targets) {
                $leaf = Split-Path $t -Leaf
                $src  = "$ShadowPath\$leaf"
                $dst  = "$OutDir\$leaf"
                try {
                    Copy-Item -LiteralPath $src -Destination $dst -Force -ErrorAction Stop
                    if (Test-Path $dst) {
                        $h = (Get-FileHash $dst -Algorithm SHA256).Hash
                        $Captured.Add([PSCustomObject]@{ File=$leaf; Source=$src; Output=$dst; SizeGB=[math]::Round((Get-Item $dst).Length/1GB,2); SHA256=$h; Method="VSS shadow copy" })
                        Write-Host "  [+] Captured $leaf" -ForegroundColor Green
                        Write-Log "Captured $leaf via VSS | SHA256: $h"
                    }
                } catch {
                    Write-Log "Could not copy $leaf from shadow: $_" "WARN"
                    $Captured.Add([PSCustomObject]@{ File=$leaf; Source=$src; Output=$null; SizeGB=$null; SHA256=$null; Method="failed - $($_.Exception.Message)" })
                }
            }
        } else {
            Write-Warning "[!] No VSS shadow copy available - cannot raw-capture locked files. Image the disk offline instead."
            Write-Log "No shadow available - raw capture skipped" "WARN"
        }
    }
}

# -- Evidence manifest -----------------------------------------------------------
$Evidence = [PSCustomObject]@{
    ChainOfCustody = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAtUTC=([DateTime]::UtcNow).ToString("o"); ToolVersion=$Global:DFIR_ToolVersion; IsAdmin=$IsAdmin }
    ArtifactType   = "PagefileHiberfil"
    Configuration  = [PSCustomObject]@{
        PageFileSettings      = $PageFileSettings
        PageFileUsage         = $PageFileUsage
        PagingFilesRegistry   = $PagingFilesReg
        ClearPageFileAtShutdown = $ClearAtShutdown   # 1 = pagefile wiped at shutdown (evidence loss risk)
        HibernateEnabled      = $HibernateEnabled
    }
    Files          = $FileMeta
    RawCaptureRequested = $DoCopy
    CapturedFiles  = $Captured
    ParseNote      = "hiberfil.sys: convert with hibr2bin / Volatility 'imagecopy' then analyze in Volatility3. pagefile.sys: carve with bulk_extractor, strings, or Volatility page-file plugins. If ClearPageFileAtShutdown=1, paged secrets are wiped on clean shutdown."
}

$Evidence | ConvertTo-Json -Depth 6 | Out-File $JsonFile -Encoding UTF8
$Hash = Get-FileHash $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=([DateTime]::UtcNow).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] Pagefile/Hiberfil documentation complete | Files described: $($FileMeta.Count) | Raw captured: $($Captured.Count)" -ForegroundColor Green
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed | Described: $($FileMeta.Count) | Captured: $($Captured.Count)"
