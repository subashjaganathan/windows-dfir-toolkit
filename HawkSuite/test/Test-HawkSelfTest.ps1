<#
.SYNOPSIS
    HawkSuite end-to-end self-test. No admin required.

    Builds the synthetic typed-artifact session (New-TestSession.ps1), imports
    it through the analyzer with an isolated config that includes an IOC list
    matching planted indicators, then asserts MRI scoring, event/IOC findings,
    and HTML report generation all behave. Exit code 0 = all pass.

    Raw-parser coverage (EVTX/prefetch/shimcache/amcache) is exercised
    separately by Test-RawParsers.ps1.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$Suite   = Resolve-Path (Join-Path $PSScriptRoot '..')
$dotnet  = 'C:\Program Files\dotnet\dotnet.exe'
$hawkDll = Join-Path $Suite 'Analyzer\src\Hawk.Analyzer\bin\Debug\net8.0-windows\hawk.dll'
if (-not (Test-Path $hawkDll)) { throw "Build the analyzer first (Debug). Missing: $hawkDll" }

$pass = 0; $fail = 0
function Assert($name, [bool]$cond, $detail = '') {
    if ($cond) { Write-Host "  [PASS] $name" -ForegroundColor Green; $script:pass++ }
    else       { Write-Host "  [FAIL] $name $detail" -ForegroundColor Red;   $script:fail++ }
}
function Hawk { & $dotnet exec $hawkDll @args 2>&1 | Out-String }

Write-Host "`n=== Hawk self-test ===" -ForegroundColor Cyan

# --- 1. build the synthetic typed session ------------------------------------
& (Join-Path $PSScriptRoot 'New-TestSession.ps1') | Out-Null
$hawk = Join-Path $PSScriptRoot 'TEST-002_TEST-HOST.hawk'
Assert 'synthetic session built' (Test-Path $hawk)

# --- 2. isolated config with an IOC list matching planted indicators ----------
$cfg = Join-Path $env:TEMP "hawk_selftest_cfg"
if (Test-Path $cfg) { Remove-Item $cfg -Recurse -Force }
Copy-Item (Join-Path $Suite 'Configuration') $cfg -Recurse
@'
type,value,note
ip,203.0.113.7,self-test planted C2
domain,evil-c2.example.net,self-test planted C2 domain
'@ | Out-File (Join-Path $cfg 'IOC\selftest.csv') -Encoding utf8
$env:HAWK_CONFIG = $cfg

# clean any prior analysis dir (OneDrive lock-safe)
$analysis = Join-Path $PSScriptRoot 'TEST-002_TEST-HOST_analysis'
if (Test-Path $analysis) { cmd /c "rmdir /s /q `"$analysis`"" 2>$null }

# --- 3. import + score --------------------------------------------------------
$importOut = Hawk import $hawk
$db = Join-Path $analysis 'hawk.db'
Assert 'import produced hawk.db' (Test-Path $db) "(import said: $($importOut -split "`n" | Select-Object -Last 1))"
Assert 'IOC matcher ran' ($importOut -match 'IOC')

# --- 4. MRI scoring assertions ------------------------------------------------
$wl = Hawk worklist $db
Assert 'masquerading svchost scored critical/high' ($wl -match 'svchost' -and ($wl -match 'critical|high'))
Assert 'encoded-powershell rule fired'             ($wl -match 'encoded-powershell')
Assert 'office-spawned-shell rule fired'           ($wl -match 'started-by-shell-from-office')

$ps = Hawk persistence $db
Assert 'WMI script consumer scored'  ($ps -match 'wmi-activescript-consumer')
Assert 'certutil LOLBAS task scored' ($ps -match 'lolbas-suspicious-args')
Assert 'shell-service scored'        ($ps -match 'service-runs-shell')

# --- 5. findings: IOC matches -------------------------------------------------
$fd = Hawk findings $db
Assert 'IOC network-ip match (203.0.113.7)' ($fd -match 'ioc-network-ip' -and $fd -match '203\.0\.113\.7')
Assert 'IOC domain match (evil-c2)'         ($fd -match 'ioc-domain'     -and $fd -match 'evil-c2')

# --- 6. HTML report -----------------------------------------------------------
$report = Join-Path $env:TEMP 'hawk_selftest_report.html'
if (Test-Path $report) { Remove-Item $report -Force }
Hawk report $db -o $report | Out-Null
Assert 'report file generated' (Test-Path $report)
if (Test-Path $report) {
    $html = Get-Content $report -Raw
    Assert 'report has executive summary' ($html -match 'Executive Summary')
    Assert 'report lists findings'        ($html -match 'Findings')
    Assert 'report shows IOC hit'         ($html -match '203\.0\.113\.7|evil-c2')
    Assert 'report is self-contained (no external src)' ($html -notmatch '<script' -and $html -notmatch 'src="http')
    Assert 'report respects [UNKNOWN] convention' ($html -notmatch '1970-01-01')
}

# --- cleanup ------------------------------------------------------------------
Remove-Item Env:\HAWK_CONFIG -ErrorAction SilentlyContinue
Remove-Item $cfg -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "`n=== $pass passed, $fail failed ===" -ForegroundColor ($(if ($fail) {'Red'} else {'Green'}))
exit $fail
