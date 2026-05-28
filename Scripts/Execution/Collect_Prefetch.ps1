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
    ChainOfCustody  = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=(Get-Date).ToString("o"); ToolVersion="1.0"; IsServer=$IsServer }
    PrefetchConfig  = $PrefetchConfig
    FileCount       = $ManifestData.Count
    OutputDirectory = $OutDir
    Data            = $ManifestData
    ServerFallback  = $ServerFallback
}

$Manifest | ConvertTo-Json -Depth 6 | Out-File -FilePath $ManifestFile -Encoding UTF8
$Hash = Get-FileHash -Path $ManifestFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$ManifestFile; Hash=$Hash.Hash; Generated=(Get-Date).ToString("o") } |
    ConvertTo-Json | Out-File -FilePath $HashFile -Encoding UTF8

Write-Host "[+] Prefetch collection completed ($($ManifestData.Count) files)" -ForegroundColor Green
if ($IsServer) { Write-Host "[+] Server fallback artifacts also collected" -ForegroundColor Cyan }
Write-Host "[+] Output Dir: $OutDir" -ForegroundColor Green
Write-Log "Completed"
