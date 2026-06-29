<#
.SYNOPSIS
    Downloads the NIST NSRL RDS (known-good hash set) and builds Hawk's
    nsrl.bloom whitelist, so the analyzer suppresses known-good binaries
    (the single biggest false-positive reduction).

.DESCRIPTION
    NSRL RDS "modern minimal" is distributed by NIST as a large ZIP containing
    an RDSv3 SQLite database. This script fetches it (or uses an already-
    downloaded copy), then runs `hawk whitelist build` to produce
    Configuration/Whitelist/nsrl.bloom.

    The RDS download is multi-GB; run this once on a machine with bandwidth and
    disk to spare, then copy the resulting nsrl.bloom alongside hawk.exe.

.PARAMETER Url
    Direct URL to an NSRL RDS distribution (ZIP, .db/.sqlite, NSRLFile.txt, or
    plain md5-per-line .txt). Get the current link from:
      https://www.nist.gov/itl/ssd/software-quality-group/nsrl-download
    (the "RDS modern minimal" set is recommended).

.PARAMETER InputPath
    Use an already-downloaded RDS file or folder instead of downloading.

.PARAMETER HawkExe
    Path to hawk.exe (defaults to ..\dist\hawk.exe).

.EXAMPLE
    .\Get-NsrlWhitelist.ps1 -Url https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/.../RDS_2025_modern_minimal.zip

.EXAMPLE
    .\Get-NsrlWhitelist.ps1 -InputPath D:\NSRL\RDS_modern_minimal.db
#>
[CmdletBinding(DefaultParameterSetName = 'Download')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Download')]
    [string]$Url,

    [Parameter(Mandatory, ParameterSetName = 'Local')]
    [string]$InputPath,

    [string]$HawkExe   = (Join-Path $PSScriptRoot '..\dist\hawk.exe'),
    [string]$OutputDir = (Join-Path $PSScriptRoot '..\Configuration\Whitelist'),
    [string]$WorkDir   = (Join-Path $env:TEMP 'hawk_nsrl')
)
$ErrorActionPreference = 'Stop'

if (-not (Test-Path $HawkExe)) { throw "hawk.exe not found at $HawkExe (publish the analyzer first, or pass -HawkExe)." }
New-Item -ItemType Directory -Force $WorkDir | Out-Null

# --- 1. obtain the RDS distribution -------------------------------------------
if ($PSCmdlet.ParameterSetName -eq 'Download') {
    $dl = Join-Path $WorkDir ([IO.Path]::GetFileName(($Url -split '\?')[0]))
    if (-not $dl -or $dl -eq $WorkDir) { $dl = Join-Path $WorkDir 'nsrl_download.bin' }
    Write-Host "[*] Downloading NSRL RDS (this is multi-GB and will take a while)..." -ForegroundColor Cyan
    Write-Host "    $Url"
    try {
        # BITS is resumable and progress-aware; fall back to Invoke-WebRequest.
        Import-Module BitsTransfer -ErrorAction Stop
        Start-BitsTransfer -Source $Url -Destination $dl -DisplayName 'NSRL RDS'
    } catch {
        Write-Host "    BITS unavailable, using Invoke-WebRequest..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $Url -OutFile $dl
    }
    $InputPath = $dl
    Write-Host "[+] Downloaded: $dl ($([math]::Round((Get-Item $dl).Length/1GB,2)) GB)"
}

if (-not (Test-Path $InputPath)) { throw "Input not found: $InputPath" }

# --- 2. extract if it's a zip -------------------------------------------------
$buildInputs = @()
if ([IO.Path]::GetExtension($InputPath) -eq '.zip') {
    $extract = Join-Path $WorkDir 'extracted'
    New-Item -ItemType Directory -Force $extract | Out-Null
    Write-Host "[*] Extracting $([IO.Path]::GetFileName($InputPath))..." -ForegroundColor Cyan
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory($InputPath, $extract)
    # prefer a SQLite DB, else any NSRLFile.txt / *.txt
    $db  = Get-ChildItem $extract -Recurse -Include '*.db','*.sqlite' -ErrorAction SilentlyContinue | Select-Object -First 1
    $txt = Get-ChildItem $extract -Recurse -Include 'NSRLFile.txt','*.txt'  -ErrorAction SilentlyContinue | Select-Object -First 1
    if     ($db)  { $buildInputs = @($db.FullName) }
    elseif ($txt) { $buildInputs = @($txt.FullName) }
    else { throw "No .db/.sqlite or NSRLFile.txt found inside the ZIP." }
} else {
    $buildInputs = @($InputPath)
}

# --- 3. build the bloom filter ------------------------------------------------
Write-Host "[*] Building nsrl.bloom -> $OutputDir" -ForegroundColor Cyan
& $HawkExe whitelist build @buildInputs -o $OutputDir
if ($LASTEXITCODE -ne 0) { throw "hawk whitelist build failed (exit $LASTEXITCODE)." }

$bloom = Join-Path $OutputDir 'nsrl.bloom'
if (Test-Path $bloom) {
    Write-Host "[+] Whitelist ready: $bloom ($([math]::Round((Get-Item $bloom).Length/1MB,1)) MB)" -ForegroundColor Green
    Write-Host "    Every future 'hawk import' now suppresses NSRL-known binaries."
    Write-Host "    Ship nsrl.bloom in Configuration\Whitelist next to hawk.exe."
} else {
    throw "build reported success but nsrl.bloom not found."
}
