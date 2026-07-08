#Requires -Version 5.1
<#
.SYNOPSIS
    Matches user-supplied indicators of compromise against all collected evidence.

.DESCRIPTION
    Loads IOC indicators the investigator provides (file hashes, IP addresses, domains,
    filenames) and searches every collected evidence JSON for them, surfacing hits with the
    artifact they were found in. This complements IOC_ThreatIntel (which enriches extracted
    IOCs via VirusTotal) by letting responders sweep for KNOWN indicators from a prior case,
    threat feed or advisory.

    IOC sources (first that exists wins):
      1. $env:DFIR_IOC_FILE  - explicit path to a .txt/.csv indicator file
      2. <ToolkitRoot>\IOCs\  - any .txt/.csv files dropped in this folder
      3. $env:DFIR_OUTPUT\IOCs\ - IOC files staged alongside the evidence

    Indicator file format: one indicator per line. Either "type,value" (type =
    sha256|sha1|md5|ip|domain|filename) or a bare value whose type is auto-detected. Lines
    starting with # are comments.

.IR_PHASE
    Analysis / Reporting

.MITRE_ATTCK
    Detection support across techniques (IOC sweeping)

.FORENSIC_SAFETY
    Read-only - reads evidence JSON already collected; touches nothing on the live system.

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

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
# Output named "IndicatorMatch_*" (not "IOC_*") so the IR report's evidence loader (which
# skips IOC_* files) still picks it up.
$LogFile   = "$BasePath\IndicatorMatch_Execution.log"
$JsonFile  = "$BasePath\IndicatorMatch_${Hostname}_${Timestamp}.json"
$ToolkitRoot = if ($PSScriptRoot) { Split-Path (Split-Path $PSScriptRoot) } else { (Get-Location).Path }

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "IOC match started | Case: $CaseNum"

# -- Locate IOC source files ---------------------------------------------------
$IocFiles = @()
if ($env:DFIR_IOC_FILE -and (Test-Path $env:DFIR_IOC_FILE)) {
    $IocFiles = @($env:DFIR_IOC_FILE)
} elseif (Test-Path (Join-Path $ToolkitRoot "IOCs")) {
    $IocFiles = @(Get-ChildItem (Join-Path $ToolkitRoot "IOCs") -Include *.txt,*.csv -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
} elseif (Test-Path (Join-Path $BasePath "IOCs")) {
    $IocFiles = @(Get-ChildItem (Join-Path $BasePath "IOCs") -Include *.txt,*.csv -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
}

function Get-IocType { param([string]$v)
    if ($v -match '^[0-9a-fA-F]{64}$') { return "sha256" }
    if ($v -match '^[0-9a-fA-F]{40}$') { return "sha1" }
    if ($v -match '^[0-9a-fA-F]{32}$') { return "md5" }
    if ($v -match '^(\d{1,3}\.){3}\d{1,3}$') { return "ip" }
    if ($v -match '^(?=.{1,253}$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$') { return "domain" }
    return "filename"
}
function New-IocRegex { param([string]$Type,[string]$Value)
    $e = [regex]::Escape($Value)
    switch ($Type) {
        "sha256" { "(?i)(?<![0-9a-f])$e(?![0-9a-f])" }
        "sha1"   { "(?i)(?<![0-9a-f])$e(?![0-9a-f])" }
        "md5"    { "(?i)(?<![0-9a-f])$e(?![0-9a-f])" }
        "ip"     { "(?<![\d.])$e(?![\d.])" }
        "domain" { "(?i)(?<![\w.-])$e(?![\w-])" }
        default  { "(?i)$e" }
    }
}

# -- Parse indicators (note: $Matches below is PowerShell's automatic regex variable) --------
$Indicators = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($f in $IocFiles) {
    foreach ($line in ([System.IO.File]::ReadAllLines($f))) {
        $l = $line.Trim()
        if (-not $l -or $l.StartsWith("#")) { continue }
        if ($l -match '^(sha256|sha1|md5|ip|domain|filename)\s*,\s*(.+)$') {
            $type = $Matches[1].ToLower(); $val = $Matches[2].Trim()
        } else {
            $val = ($l -split '[,\t]')[0].Trim(); $type = Get-IocType $val
        }
        if ($val) { $Indicators.Add([PSCustomObject]@{ Type=$type; Value=$val; Source=(Split-Path $f -Leaf); Rx=(New-IocRegex $type $val) }) }
    }
}
$Indicators = @($Indicators | Sort-Object Type,Value -Unique)
Write-Log "Loaded $($Indicators.Count) indicators from $($IocFiles.Count) file(s)"

# -- Load evidence and match (list name avoids the automatic $Matches variable) --------------
$IocHits = [System.Collections.Generic.List[PSCustomObject]]::new()
$Scanned = 0
if ($Indicators.Count -gt 0) {
    $EvidenceFiles = @(Get-ChildItem $BasePath -Filter *.json -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notmatch "\.hash\.json$|Manifest|_Report_|IndicatorMatch|IOC_" })
    foreach ($ef in $EvidenceFiles) {
        $text = $null
        try { $text = [System.IO.File]::ReadAllText($ef.FullName) } catch { continue }
        if (-not $text) { continue }
        $Scanned++
        $artType = ([regex]::Match($text, '"ArtifactType"\s*:\s*"([^"]+)"')).Groups[1].Value
        foreach ($i in $Indicators) {
            $mc = ([regex]::Matches($text, $i.Rx)).Count
            if ($mc -gt 0) {
                $IocHits.Add([PSCustomObject]@{
                    Indicator=$i.Value; Type=$i.Type; Source=$i.Source
                    EvidenceFile=$ef.Name; ArtifactType=$artType; Occurrences=$mc
                })
            }
        }
    }
}
$MatchedIndicators = @($IocHits | Select-Object -ExpandProperty Indicator -Unique).Count
Write-Log "Scanned $Scanned evidence files; $($IocHits.Count) hit(s) across $MatchedIndicators indicator(s)"

$Findings = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($grp in ($IocHits | Group-Object Indicator)) {
    $first = $grp.Group | Select-Object -First 1
    $arts  = @($grp.Group | Select-Object -ExpandProperty ArtifactType -Unique) -join ", "
    $Findings.Add([PSCustomObject]@{ Severity="HIGH"; Type=$first.Type; Indicator=$grp.Name; Detail="Matched in: $arts"; Hits=$grp.Count })
}

$Note = if ($Indicators.Count -eq 0) {
    "No user IOCs provided. Supply indicators via `$env:DFIR_IOC_FILE, a IOCs\ folder in the toolkit root, or an IOCs\ folder in the output directory (one indicator per line; optional 'type,value')."
} elseif ($IocHits.Count -eq 0) {
    "No user indicators matched the collected evidence."
} else { "$MatchedIndicators of $($Indicators.Count) supplied indicators matched." }

$Evidence = [PSCustomObject]@{
    ChainOfCustody    = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=([DateTime]::UtcNow).ToString("o"); ToolVersion=$Global:DFIR_ToolVersion }
    ArtifactType      = "IOC_Matches"
    IndicatorsLoaded  = $Indicators.Count
    IndicatorSources  = @($IocFiles | ForEach-Object { Split-Path $_ -Leaf })
    EvidenceScanned   = $Scanned
    MatchCount        = $IocHits.Count
    MatchedIndicators = $MatchedIndicators
    Findings          = $Findings
    Matches           = $IocHits
    Note              = $Note
}
$Evidence | ConvertTo-Json -Depth 6 | Out-File -FilePath $JsonFile -Encoding UTF8
$Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=([DateTime]::UtcNow).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] IOC match complete | indicators: $($Indicators.Count) | matches: $($IocHits.Count) across $MatchedIndicators indicator(s)" -ForegroundColor $(if($IocHits.Count){"Red"}else{"Green"})
if ($Indicators.Count -eq 0) { Write-Host "    (no user IOCs supplied - see Note in output for how to provide them)" -ForegroundColor Yellow }
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed"
