#Requires -Version 5.1
<#
.SYNOPSIS
    Collects Windows Prefetch files and enables Prefetch on Server if needed.

.DESCRIPTION
    Copies all .pf files from C:\Windows\Prefetch to a timestamped
    evidence directory. On Windows Server where Prefetch is disabled
    by default, detects the state and reports it. If Prefetch was
    recently enabled, collects whatever exists.
    On Server OS, also collects RecentFileCache.bcf as alternate
    execution evidence.

.COMPATIBILITY
    Windows 10/11   : Full - Prefetch enabled by default
    Server 2016+    : Collects if enabled; reports registry state;
                      also collects RecentFileCache.bcf as fallback

.IR_PHASE
    Execution Evidence / Live Response

.MITRE_ATTCK
    T1059 - Command and Scripting Interpreter
    T1204 - User Execution
    T1036 - Masquerading

.FORENSIC_SAFETY
    Read-only copy - original Prefetch files are never modified.

.AUTHOR
    DFIR Toolkit

.VERSION
    2.1
#>

Set-StrictMode -Off
$ErrorActionPreference = "Continue"


# --- Shared toolkit module: single source of truth for version + base paths ---
$__DFIRMod = Join-Path $PSScriptRoot '..\Infrastructure\DFIR_Common.psm1'
if (Test-Path $__DFIRMod) { Import-Module $__DFIRMod -Force -ErrorAction SilentlyContinue }
if (-not $Global:DFIR_ToolVersion) { $Global:DFIR_ToolVersion = '1.0' }
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) { Write-Error "[!] This script must be run as Administrator. Exiting."; exit 1 }

$Timestamp     = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname      = $env:COMPUTERNAME
$BaseDir       = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$OutDir        = "$BaseDir\Prefetch_${Hostname}_${Timestamp}"
$LogFile       = "$BaseDir\Prefetch_Execution.log"
$ManifestFile  = "$OutDir\Prefetch_Manifest_${Hostname}_${Timestamp}.json"
$HashFile      = "$ManifestFile.hash.json"
$PrefetchPath  = "C:\Windows\Prefetch"
$CaseNum       = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "Prefetch collection started | Case: $CaseNum"

# -- Prefetch (.pf) parser -----------------------------------------------------
# Win8+ .pf files are XPRESS-Huffman compressed (MAM\x04 header); decompress via ntdll
# RtlDecompressBufferEx, then parse the SCCA structure for executable name, run count and the
# last-run timestamps. This puts real execution times on the forensic timeline instead of just
# copying the raw files. The original .pf is still copied for offline verification (PECmd).
if (-not ([System.Management.Automation.PSTypeName]'HawkPf.Decomp').Type) {
    try {
        Add-Type -Namespace HawkPf -Name Decomp -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("ntdll.dll")]
public static extern int RtlGetCompressionWorkSpaceSize(ushort Format, out uint BufWs, out uint FragWs);
[System.Runtime.InteropServices.DllImport("ntdll.dll")]
public static extern int RtlDecompressBufferEx(ushort Format, byte[] Out, uint OutLen, byte[] In, uint InLen, out uint Final, byte[] Ws);
'@
    } catch { Write-Log "Prefetch decompressor P/Invoke unavailable: $_" "WARN" }
}

function Expand-PrefetchBytes {
    param([byte[]]$Raw)
    if ($Raw.Length -lt 8) { return $Raw }
    # "MAM" + 0x04 = XPRESS Huffman compressed (Windows 8+). Otherwise assume raw SCCA (Win7).
    if ($Raw[0] -eq 0x4D -and $Raw[1] -eq 0x41 -and $Raw[2] -eq 0x4D) {
        $uncompSize = [BitConverter]::ToUInt32($Raw, 4)
        if ($uncompSize -le 0 -or $uncompSize -gt 32MB) { throw "implausible uncompressed size $uncompSize" }
        $comp = New-Object byte[] ($Raw.Length - 8)
        [Array]::Copy($Raw, 8, $comp, 0, $comp.Length)
        $out = New-Object byte[] $uncompSize
        $bufWs = 0; $fragWs = 0
        [void][HawkPf.Decomp]::RtlGetCompressionWorkSpaceSize(4, [ref]$bufWs, [ref]$fragWs)   # 4 = XPRESS_HUFFMAN
        $ws = New-Object byte[] ([Math]::Max($bufWs,1))
        $final = 0
        $st = [HawkPf.Decomp]::RtlDecompressBufferEx(4, $out, $uncompSize, $comp, $comp.Length, [ref]$final, $ws)
        if ($st -ne 0) { throw "RtlDecompressBufferEx status 0x$($st.ToString('X'))" }
        return $out
    }
    return $Raw
}

function ConvertFrom-Scca {
    param([byte[]]$d)
    if ($null -eq $d -or $d.Length -lt 84) { return $null }
    if ([Text.Encoding]::ASCII.GetString($d, 4, 4) -ne "SCCA") { return $null }
    $ver = [BitConverter]::ToInt32($d, 0)
    $exe = ([Text.Encoding]::Unicode.GetString($d, 16, 60) -split "`0")[0]
    # Version-specific offsets: v23 (Win7) has 1 last-run time @0x80, run count @0x98;
    # v26/30/31 (Win8.1/10/11) have 8 last-run times @0x80, run count @0xD0.
    switch ($ver) {
        23      { $lrOff=0x80; $nRuns=1; $rcOff=0x98 }
        default { $lrOff=0x80; $nRuns=8; $rcOff=0xD0 }   # 26/30/31 and forward-compatible
    }
    $runCount = if ($d.Length -ge $rcOff + 4) { [BitConverter]::ToInt32($d, $rcOff) } else { $null }
    $times = @()
    for ($i = 0; $i -lt $nRuns; $i++) {
        $o = $lrOff + ($i * 8)
        if ($d.Length -ge $o + 8) {
            $ft = [BitConverter]::ToInt64($d, $o)
            if ($ft -gt 0) {
                try { $dt = [DateTime]::FromFileTimeUtc($ft); if ($dt.Year -ge 2000 -and $dt.Year -le 2100) { $times += $dt.ToString("o") } } catch {}
            }
        }
    }
    [PSCustomObject]@{ Version=$ver; ExecutableName=$exe; RunCount=$runCount; LastRunTimes=$times }
}

# -- OS Detection --------------------------------------------------------------
$OSInfo    = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$OSCaption = $OSInfo.Caption
$IsServer  = $OSCaption -match "Server"
$OSBuild   = [int]$OSInfo.BuildNumber
Write-Log "OS: $OSCaption (Build $OSBuild) | IsServer: $IsServer"

# -- Prefetch Registry State ---------------------------------------------------
Write-Host "[*] Checking Prefetch configuration..." -ForegroundColor Cyan
$PrefetchRegKey  = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"
$PrefetchEnabled = (Get-ItemProperty $PrefetchRegKey -ErrorAction SilentlyContinue).EnablePrefetcher
$SuperfetchEnabled = (Get-ItemProperty $PrefetchRegKey -ErrorAction SilentlyContinue).EnableSuperfetch

$PrefetchConfig = [PSCustomObject]@{
    EnablePrefetcher   = $PrefetchEnabled
    EnableSuperfetch   = $SuperfetchEnabled
    PrefetcherStatus   = switch ($PrefetchEnabled) {
        0 {"Disabled"} 1 {"App Launch Only"} 2 {"Boot Only"} 3 {"Enabled (App+Boot)"} default {"Unknown"}
    }
    IsServer           = $IsServer
    OSCaption          = $OSCaption
    Note               = if ($IsServer -and $PrefetchEnabled -eq 0) {
        "Server OS with Prefetch disabled (default). Enable with: Set-ItemProperty '$PrefetchRegKey' -Name EnablePrefetcher -Value 3"
    } else { "Prefetch active" }
}
Write-Log "Prefetch state: $($PrefetchConfig.PrefetcherStatus)"

# -- Collect Prefetch Files if Available ---------------------------------------
$ManifestData = [System.Collections.Generic.List[PSCustomObject]]::new()

if (Test-Path $PrefetchPath) {
    $PfFiles = @(Get-ChildItem -Path $PrefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue)
    if ($PfFiles.Count -gt 0) {
        Write-Host "[*] Copying $($PfFiles.Count) prefetch files..." -ForegroundColor Cyan
        Write-Log "Copying $($PfFiles.Count) .pf files"
        foreach ($File in $PfFiles) {
            try {
                $Dest     = Join-Path $OutDir $File.Name
                Copy-Item -Path $File.FullName -Destination $Dest -Force -ErrorAction Stop
                $FileHash = (Get-FileHash -Path $Dest -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                # Parse the copied .pf for execution evidence (best-effort; never fails the copy).
                $Parsed = $null
                try { $Parsed = ConvertFrom-Scca (Expand-PrefetchBytes ([System.IO.File]::ReadAllBytes($Dest))) } catch { Write-Log "Parse failed for $($File.Name): $_" "WARN" }
                $ManifestData.Add([PSCustomObject]@{
                    FileName          = $File.Name
                    OriginalPath      = $File.FullName
                    CopiedPath        = $Dest
                    FileSizeBytes     = $File.Length
                    CreationTimeUtc   = $File.CreationTimeUtc.ToString("o")
                    LastWriteTimeUtc  = $File.LastWriteTimeUtc.ToString("o")
                    LastAccessTimeUtc = $File.LastAccessTimeUtc.ToString("o")
                    SHA256            = $FileHash
                    CopyStatus        = "Success"
                    ExecutableName    = if ($Parsed) { $Parsed.ExecutableName } else { $null }
                    RunCount          = if ($Parsed) { $Parsed.RunCount } else { $null }
                    LastRunTimes      = if ($Parsed) { $Parsed.LastRunTimes } else { @() }
                    SccaVersion       = if ($Parsed) { $Parsed.Version } else { $null }
                    Parsed            = [bool]$Parsed
                })
            } catch {
                $ManifestData.Add([PSCustomObject]@{ FileName=$File.Name; CopyStatus="Failed: $_"; SHA256=$null })
                Write-Log "ERROR copying $($File.Name): $_" "ERROR"
            }
        }
    } else {
        Write-Warning "[!] Prefetch folder exists but contains no .pf files"
        Write-Log "Prefetch folder empty" "WARN"
    }
} else {
    Write-Warning "[!] Prefetch folder not found - Prefetch is disabled on this system"
    Write-Log "Prefetch folder not found" "WARN"
}

# -- Server Fallback: RecentFileCache.bcf + AppCompatCache --------------------
$ServerFallback = [PSCustomObject]@{ Collected = $false }

if ($IsServer) {
    Write-Host "[*] Server OS detected - collecting alternate execution artifacts..." -ForegroundColor Cyan
    Write-Log "Collecting server-specific execution artifacts"

    # RecentFileCache.bcf - execution evidence on Server
    $RFCPath = "C:\Windows\AppCompat\Programs\RecentFileCache.bcf"
    $RFCCopied = $false
    if (Test-Path $RFCPath) {
        $RFCDest = "$OutDir\RecentFileCache.bcf"
        try {
            Copy-Item $RFCPath $RFCDest -Force -ErrorAction Stop
            $RFCCopied = $true
            Write-Log "RecentFileCache.bcf copied"
        } catch { Write-Log "RecentFileCache copy failed: $_" "WARN" }
    }

    # AmCache hive path for server
    $AmCachePath = "C:\Windows\AppCompat\Programs\Amcache.hve"
    $AmCacheExists = Test-Path $AmCachePath -ErrorAction SilentlyContinue

    # SysCache hive
    $SysCachePath = "C:\Windows\System32\config\SYSTEM"

    # Prefetch enable recommendation
    $EnableCmd = "Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -Name EnablePrefetcher -Value 3; Restart-Service SysMain -Force"

    $ServerFallback = [PSCustomObject]@{
        Collected              = $true
        RecentFileCacheCopied  = $RFCCopied
        RecentFileCachePath    = if ($RFCCopied) { "$OutDir\RecentFileCache.bcf" } else { $null }
        AmCacheHiveExists      = $AmCacheExists
        AmCacheHivePath        = $AmCachePath
        AmCacheNote            = "Copy Amcache.hve offline and parse with AmcacheParser.exe (Eric Zimmerman)"
        EnablePrefetchOnServer = $EnableCmd
        Note                   = "On Server OS use AmcacheParser + RecentFileCache for execution history"
    }
    Write-Log "Server fallback artifacts collected. RecentFileCache: $RFCCopied | AmCache: $AmCacheExists"
}

# -- Manifest ------------------------------------------------------------------
$Manifest = [PSCustomObject]@{
    ArtifactType    = "PrefetchFiles"
    ChainOfCustody  = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=([DateTime]::UtcNow).ToString("o"); ToolVersion=$Global:DFIR_ToolVersion; IsServer=$IsServer }
    PrefetchConfig  = $PrefetchConfig
    FileCount       = $ManifestData.Count
    ParsedCount     = @($ManifestData | Where-Object { $_.Parsed }).Count
    OutputDirectory = $OutDir
    Data            = $ManifestData
    ServerFallback  = $ServerFallback
}

$Manifest | ConvertTo-Json -Depth 6 | Out-File -FilePath $ManifestFile -Encoding UTF8
$Hash = Get-FileHash -Path $ManifestFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$ManifestFile; Hash=$Hash.Hash; Generated=([DateTime]::UtcNow).ToString("o") } |
    ConvertTo-Json | Out-File -FilePath $HashFile -Encoding UTF8

Write-Host "[+] Prefetch collection completed ($($ManifestData.Count) files)" -ForegroundColor Green
if ($IsServer) { Write-Host "[+] Server fallback artifacts also collected" -ForegroundColor Cyan }
Write-Host "[+] Output Dir: $OutDir" -ForegroundColor Green
Write-Log "Completed"
