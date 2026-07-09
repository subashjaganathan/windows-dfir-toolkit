#Requires -Version 5.1
<#
.SYNOPSIS
    Offline analyzer - runs the DFIR toolkit's analysis/reporting against an ALREADY-collected
    evidence set, on a clean analyst workstation (not on the target).

.DESCRIPTION
    Best-practice IR separates COLLECTION (runs on the possibly-compromised target) from ANALYSIS
    (runs off-host on a trusted workstation). Run_IR_Collection.ps1 collects; this script analyzes.

    Point it at a collected evidence directory (the folder containing the *.json artifacts and the
    Evidence_Manifest_*.json) and it:
      1. Verifies evidence integrity against the manifest (Verify-Evidence.ps1) unless -SkipVerify.
      2. Runs the reporting/enrichment pipeline against that evidence:
           - IOC_Match          (user-supplied indicator sweep)
           - Generate_IR_Report (risk-scored HTML report)
           - Timeline_Builder   (unified MACB timeline)
           - IOC_ThreatIntel    (VirusTotal enrichment - needs VT_API_KEY; internet FROM the
                                 analyst box, never the target)

    It COLLECTS NOTHING from the local machine - it only reads/reports on the supplied evidence.
    This is what lets VirusTotal enrichment and report generation happen off the target, avoiding
    attacker-visible network traffic and extra footprint on the box under investigation.

.PARAMETER EvidencePath
    Path to the collected evidence directory (contains the artifact *.json and Evidence_Manifest_*).

.PARAMETER SkipVerify
    Skip the pre-analysis integrity verification step.

.EXAMPLE
    # On the analyst workstation, after copying the sealed evidence off the target:
    $env:VT_API_KEY = "..."   # optional, for VirusTotal enrichment
    .\Analyze-Evidence.ps1 -EvidencePath D:\Cases\IR-2026-001\evidence

.FORENSIC_SAFETY
    Read-only with respect to the target: collects nothing. Writes reports into EvidencePath.

.AUTHOR
    Subash J

.VERSION
    1.0
#>
param(
    [Parameter(Mandatory=$true)][string]$EvidencePath,
    [switch]$SkipVerify
)

$ErrorActionPreference = "Continue"

$ToolkitRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
if (-not (Test-Path (Join-Path $ToolkitRoot "Scripts"))) { Write-Error "[!] Scripts folder not found at: $ToolkitRoot\Scripts"; exit 1 }
if (-not (Test-Path $EvidencePath)) { Write-Error "[!] Evidence path not found: $EvidencePath"; exit 1 }

# Point the reporting scripts at the supplied evidence set (they read $env:DFIR_OUTPUT).
$env:DFIR_OUTPUT = (Resolve-Path $EvidencePath).Path

# Shared module: single source of truth for the tool version.
$__DFIRMod = Join-Path $ToolkitRoot "Scripts\Infrastructure\DFIR_Common.psm1"
if (Test-Path $__DFIRMod) { Import-Module $__DFIRMod -Force -ErrorAction SilentlyContinue }
if (-not $Global:DFIR_ToolVersion) { $Global:DFIR_ToolVersion = "1.0" }

Write-Host "+==============================================================+" -ForegroundColor Magenta
Write-Host "|         WINDOWS DFIR TOOLKIT - OFFLINE ANALYZER             |" -ForegroundColor Magenta
Write-Host "+==============================================================+" -ForegroundColor Magenta
Write-Host "  Evidence : $env:DFIR_OUTPUT" -ForegroundColor Cyan
Write-Host "  Version  : $Global:DFIR_ToolVersion" -ForegroundColor Cyan
Write-Host ""

# 0. Integrity verification first - do not analyze evidence you have not proven intact.
if (-not $SkipVerify) {
    Write-Host "--- Verifying evidence integrity ---" -ForegroundColor Magenta
    $verify = Join-Path $ToolkitRoot "Scripts\Reporting\Verify-Evidence.ps1"
    if (Test-Path $verify) {
        & $verify -BasePath $env:DFIR_OUTPUT
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "[!] Integrity verification FAILED - the evidence may be tampered or incomplete."
            Write-Warning "    Continuing analysis, but treat findings with caution (or re-copy the evidence)."
        }
    } else {
        Write-Warning "[!] Verify-Evidence.ps1 not found - skipping integrity check."
    }
    Write-Host ""
}

# 1. Reporting / enrichment pipeline (same scripts the collector runs, but off-host).
$Pipeline = @(
    @{ Name = "User IOC matching";       Path = "Scripts\Reporting\IOC_Match.ps1" }
    @{ Name = "IR report";               Path = "Scripts\Reporting\Generate_IR_Report.ps1" }
    @{ Name = "Forensic timeline";       Path = "Scripts\Reporting\Timeline_Builder.ps1" }
    @{ Name = "IOC threat-intel (VT)";   Path = "Scripts\Reporting\IOC_ThreatIntel.ps1" }
)

$ok = 0; $failed = 0
foreach ($step in $Pipeline) {
    $script = Join-Path $ToolkitRoot $step.Path
    Write-Host "--- $($step.Name) ---" -ForegroundColor Magenta
    if (-not (Test-Path $script)) { Write-Warning "  [!] Not found: $($step.Path)"; $failed++; continue }
    try { & $script; Write-Host "  [+] $($step.Name) complete" -ForegroundColor Green; $ok++ }
    catch { Write-Host "  [!] $($step.Name) failed: $_" -ForegroundColor Red; $failed++ }
    Write-Host ""
}

Write-Host "+==============================================================+" -ForegroundColor Magenta
Write-Host "|                   ANALYSIS COMPLETE                         |" -ForegroundColor Magenta
Write-Host "+==============================================================+" -ForegroundColor Magenta
Write-Host "  Steps OK : $ok | Failed: $failed" -ForegroundColor Cyan
Write-Host "  Reports written under: $env:DFIR_OUTPUT" -ForegroundColor Green
