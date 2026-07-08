#Requires -Version 5.1
<#
.SYNOPSIS
    Re-verifies the integrity of a collected evidence set against its manifest.

.DESCRIPTION
    The collection run produces Evidence_Manifest_<timestamp>.json (every artifact with its
    SHA256) plus a <manifest>.hash.json sidecar. This script closes the other half of the
    chain-of-custody loop: it independently RE-HASHES every file the manifest lists and diffs
    the result against the recorded hash, so a recipient (or a court) can prove the evidence
    is byte-for-byte unchanged since collection.

    It also verifies the manifest's own SHA256 against its .hash.json sidecar, detecting
    tampering with the manifest itself.

    This is an OFFLINE, read-only verifier. Run it on the analyst workstation against the
    evidence package - it collects nothing and needs no privileges or network.

.PARAMETER ManifestPath
    Path to Evidence_Manifest_*.json. If omitted, the newest manifest under -BasePath is used.

.PARAMETER BasePath
    Evidence root to search when -ManifestPath is not given. Defaults to $env:DFIR_OUTPUT or
    C:\IR_Collection.

.EXAMPLE
    .\Verify-Evidence.ps1
    .\Verify-Evidence.ps1 -ManifestPath D:\Evidence\Evidence_Manifest_20260708_101500.json

.FORENSIC_SAFETY
    Read-only. Only reads and hashes existing files; writes a single verification report.

.AUTHOR
    Subash J

.VERSION
    1.1
#>
param(
    [string]$ManifestPath = "",
    [string]$BasePath = ""
)

Set-StrictMode -Off
$ErrorActionPreference = "Continue"

# --- Shared toolkit module: single source of truth for version + base paths ---
$__DFIRMod = Join-Path $PSScriptRoot '..\Infrastructure\DFIR_Common.psm1'
if (Test-Path $__DFIRMod) { Import-Module $__DFIRMod -Force -ErrorAction SilentlyContinue }
if (-not $Global:DFIR_ToolVersion) { $Global:DFIR_ToolVersion = '1.0' }

if (-not $BasePath) { $BasePath = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" } }

# Locate the manifest
if (-not $ManifestPath) {
    $ManifestPath = @(Get-ChildItem $BasePath -Filter "Evidence_Manifest_*.json" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
}
if (-not $ManifestPath -or -not (Test-Path $ManifestPath)) {
    Write-Error "[!] No manifest found. Specify -ManifestPath or ensure Evidence_Manifest_*.json exists under $BasePath"
    return
}

Write-Host "+==============================================================+" -ForegroundColor Magenta
Write-Host "|            DFIR EVIDENCE INTEGRITY VERIFICATION             |" -ForegroundColor Magenta
Write-Host "+==============================================================+" -ForegroundColor Magenta
Write-Host "[*] Manifest: $ManifestPath" -ForegroundColor Cyan

$ManifestRoot = Split-Path $ManifestPath -Parent

# 1. Verify the manifest itself against its .hash.json sidecar (tamper check on the manifest).
$ManifestVerdict = "NO SIDECAR"
$SidecarPath = "$ManifestPath.hash.json"
$RecordedManifestHash = $null
if (Test-Path $SidecarPath) {
    try {
        $Sidecar = Get-Content $SidecarPath -Raw | ConvertFrom-Json
        $RecordedManifestHash = $Sidecar.SHA256
        $ActualManifestHash = (Get-FileHash $ManifestPath -Algorithm SHA256).Hash
        $ManifestVerdict = if ($ActualManifestHash -eq $RecordedManifestHash) { "MATCH" } else { "TAMPERED" }
    } catch { $ManifestVerdict = "ERROR" }
}
$mColor = if ($ManifestVerdict -eq "MATCH") { "Green" } elseif ($ManifestVerdict -eq "NO SIDECAR") { "Yellow" } else { "Red" }
Write-Host "[*] Manifest self-integrity: $ManifestVerdict" -ForegroundColor $mColor

# 2. Load manifest and re-hash every listed evidence file.
try {
    $Manifest = Get-Content $ManifestPath -Raw | ConvertFrom-Json
} catch {
    Write-Error "[!] Manifest is not valid JSON: $_"; return
}

$Results = [System.Collections.Generic.List[PSCustomObject]]::new()
$Pass = 0; $Fail = 0; $Missing = 0
$Files = @($Manifest.EvidenceFiles)
Write-Host "[*] Verifying $($Files.Count) evidence files..." -ForegroundColor Cyan

foreach ($F in $Files) {
    # Prefer the recorded absolute path; fall back to resolving RelativePath under the manifest
    # folder so a MOVED evidence package still verifies.
    $Path = $F.FullPath
    if (-not $Path -or -not (Test-Path $Path)) {
        if ($F.RelativePath) { $Path = Join-Path $ManifestRoot $F.RelativePath }
    }

    if (-not $Path -or -not (Test-Path $Path)) {
        $Missing++
        $Results.Add([PSCustomObject]@{ File=$F.RelativePath; Verdict="MISSING"; Recorded=$F.SHA256; Actual=$null })
        Write-Host "  [MISSING] $($F.RelativePath)" -ForegroundColor Red
        continue
    }

    if (-not $F.SHA256) {
        # Some artifacts (e.g. very large captures) may have been recorded without a hash.
        $Results.Add([PSCustomObject]@{ File=$F.RelativePath; Verdict="NO HASH ON RECORD"; Recorded=$null; Actual=(Get-FileHash $Path -Algorithm SHA256).Hash })
        continue
    }

    $Actual = (Get-FileHash $Path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
    if ($Actual -eq $F.SHA256) {
        $Pass++
        $Results.Add([PSCustomObject]@{ File=$F.RelativePath; Verdict="MATCH"; Recorded=$F.SHA256; Actual=$Actual })
    } else {
        $Fail++
        $Results.Add([PSCustomObject]@{ File=$F.RelativePath; Verdict="MISMATCH"; Recorded=$F.SHA256; Actual=$Actual })
        Write-Host "  [MISMATCH] $($F.RelativePath)" -ForegroundColor Red
    }
}

# 3. Report
$Overall = if ($Fail -eq 0 -and $Missing -eq 0 -and $ManifestVerdict -in @("MATCH","NO SIDECAR")) { "VERIFIED" } else { "FAILED" }
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportFile = Join-Path $ManifestRoot "Evidence_Verification_${Timestamp}.json"

[PSCustomObject]@{
    ArtifactType        = "EvidenceVerification"
    VerifiedAtUTC       = ([DateTime]::UtcNow).ToString("o")
    VerifiedBy          = $env:USERNAME
    Manifest            = $ManifestPath
    ManifestSelfIntegrity = $ManifestVerdict
    RecordedManifestHash  = $RecordedManifestHash
    CaseNumber          = $Manifest.ChainOfCustody.CaseNumber
    TotalFiles          = $Files.Count
    Matched             = $Pass
    Mismatched          = $Fail
    Missing             = $Missing
    OverallVerdict      = $Overall
    Details             = $Results
} | ConvertTo-Json -Depth 6 | Out-File $ReportFile -Encoding UTF8

Write-Host ""
Write-Host "+==============================================================+" -ForegroundColor Magenta
Write-Host ("  RESULT: {0}" -f $Overall) -ForegroundColor $(if ($Overall -eq "VERIFIED") { "Green" } else { "Red" })
Write-Host "  Matched: $Pass | Mismatched: $Fail | Missing: $Missing | Manifest: $ManifestVerdict" -ForegroundColor Cyan
Write-Host "  Report : $ReportFile" -ForegroundColor Green
Write-Host "+==============================================================+" -ForegroundColor Magenta

# Non-zero exit on failure so CI / scripted handoff can gate on it (safe: this script is run
# standalone, never dot-sourced by the collection orchestrator).
if ($Overall -ne "VERIFIED") { exit 1 }
