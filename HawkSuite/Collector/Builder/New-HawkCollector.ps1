<#
.SYNOPSIS
    Hawk Collector Builder — generates a portable, USB-ready collector package.
    Equivalent of Redline's "Create Collector" workflow.

.DESCRIPTION
    Assembles selected collection modules + preset config + runtime into a
    self-contained folder. Run the resulting RunCollector.bat on the target
    host (elevated); it produces a single .hawk session file for import into
    Hawk Analyzer.

.EXAMPLE
    .\New-HawkCollector.ps1 -Preset standard -OutputPath E:\HawkCollector
    .\New-HawkCollector.ps1 -Preset comprehensive -CaseNumber CASE-2026-014 -OutputPath E:\HawkCollector
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('standard', 'comprehensive', 'ioc-search')]
    [string]$Preset,

    [Parameter(Mandatory)]
    [string]$OutputPath,

    [string]$CaseNumber = '',
    [string]$Investigator = '',

    # Path to the module library (the refactored collection scripts)
    [string]$ModuleLibrary = (Join-Path $PSScriptRoot '..\Modules'),

    # For ioc-search preset: IOC file determines which modules are needed
    [string]$IocFile = ''
)

$ErrorActionPreference = 'Stop'
$SuiteRoot  = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$PresetFile = Join-Path $SuiteRoot "Configuration\Presets\$Preset.json"

if (-not (Test-Path $PresetFile)) { throw "Preset config not found: $PresetFile" }
$PresetConfig = Get-Content $PresetFile -Raw | ConvertFrom-Json

Write-Host "[*] Building Hawk Collector — preset: $Preset" -ForegroundColor Cyan

# --- Layout ---------------------------------------------------------------
$Dirs = @('Modules', 'Runtime', 'Tools')
New-Item -ItemType Directory -Force $OutputPath | Out-Null
$Dirs | ForEach-Object { New-Item -ItemType Directory -Force (Join-Path $OutputPath $_) | Out-Null }

# --- Resolve module list ---------------------------------------------------
if ($PresetConfig.modules -contains '*') {
    $ModuleFiles = Get-ChildItem $ModuleLibrary -Recurse -Filter '*.ps1'
    if ($PresetConfig.excludeModules) {
        $ModuleFiles = $ModuleFiles | Where-Object {
            $rel = $_.FullName.Substring((Resolve-Path $ModuleLibrary).Path.Length + 1) -replace '\\', '/' -replace '\.ps1$', ''
            $rel -notin $PresetConfig.excludeModules
        }
    }
} else {
    $ModuleFiles = foreach ($m in $PresetConfig.modules) {
        $f = Join-Path $ModuleLibrary ($m -replace '/', '\')
        $f = "$f.ps1"
        if (Test-Path $f) { Get-Item $f } else { Write-Warning "Module not found, skipped: $m" }
    }
}

# --- Copy modules preserving category subfolders ----------------------------
foreach ($f in $ModuleFiles) {
    $rel  = $f.FullName.Substring((Resolve-Path $ModuleLibrary).Path.Length + 1)
    $dest = Join-Path $OutputPath "Modules\$rel"
    New-Item -ItemType Directory -Force (Split-Path $dest) | Out-Null
    Copy-Item $f.FullName $dest
}
Write-Host "[+] $(@($ModuleFiles).Count) modules packaged"

# --- Copy runtime (orchestrator + common module) -----------------------------
Copy-Item (Join-Path $SuiteRoot 'Collector\Runtime\Collector.ps1')    (Join-Path $OutputPath 'Runtime\Collector.ps1')
Copy-Item (Join-Path $SuiteRoot 'Collector\Runtime\Hawk.Common.psm1') (Join-Path $OutputPath 'Runtime\Hawk.Common.psm1')

# --- Write collector config --------------------------------------------------
$CollectorConfig = [ordered]@{
    schemaVersion = '1.0'
    preset        = $Preset
    caseNumber    = $CaseNumber
    investigator  = $Investigator
    builtAtUtc    = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    builtBy       = $env:USERNAME
    rawAcquisition = $PresetConfig.rawAcquisition
    eventLogDays   = $PresetConfig.eventLogDays
}
$CollectorConfig | ConvertTo-Json -Depth 6 | Out-File (Join-Path $OutputPath 'config.json') -Encoding utf8

# --- Launcher ----------------------------------------------------------------
@'
@echo off
:: Hawk Collector launcher — run as Administrator on the TARGET host.
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Administrator privileges required. Right-click ^> Run as administrator.
    pause & exit /b 1
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Runtime\Collector.ps1" -PackageRoot "%~dp0."
pause
'@ | Out-File (Join-Path $OutputPath 'RunCollector.bat') -Encoding ascii

# --- Integrity manifest of the package itself --------------------------------
$PackageHashes = Get-ChildItem $OutputPath -Recurse -File | ForEach-Object {
    [ordered]@{
        path   = $_.FullName.Substring((Resolve-Path $OutputPath).Path.Length + 1)
        sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
    }
}
@{ schemaVersion = '1.0'; files = $PackageHashes } | ConvertTo-Json -Depth 4 |
    Out-File (Join-Path $OutputPath 'package-integrity.json') -Encoding utf8

Write-Host "[+] Collector package ready: $OutputPath" -ForegroundColor Green
Write-Host "    Copy folder to USB / share, run RunCollector.bat elevated on target."
