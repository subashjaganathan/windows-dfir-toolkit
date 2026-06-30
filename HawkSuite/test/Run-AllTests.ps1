<#
.SYNOPSIS
    One-command test runner for HawkSuite (used by CI and locally).

    Gates:
      1. PowerShell parse-lint  - every collector module + runtime script parses.
      2. Build                  - the .NET 8 analyzer compiles (Debug).
      3. Test-Modules           - all collector modules execute on this host.
      4. Raw parsers            - build a synthetic .hawk, import it, assert the
                                  EVTX/prefetch/shimcache/amcache parsers ran.
      5. Test-HawkSelfTest      - end-to-end import -> score -> IOC -> report.

    Exit code = number of failed gates (0 = all green). No admin required.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Continue'
$Suite  = Resolve-Path (Join-Path $PSScriptRoot '..')
$dotnet = if (Test-Path 'C:\Program Files\dotnet\dotnet.exe') { 'C:\Program Files\dotnet\dotnet.exe' } else { 'dotnet' }
$proj   = Join-Path $Suite 'Analyzer\src\Hawk.Analyzer\Hawk.Analyzer.csproj'
$dll    = Join-Path $Suite 'Analyzer\src\Hawk.Analyzer\bin\Debug\net8.0-windows\hawk.dll'
$fails  = 0
function Section($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }

# 1. Parse-lint -----------------------------------------------------------------
Section '1/5 PowerShell parse-lint'
$psFiles = Get-ChildItem (Join-Path $Suite 'Collector') -Recurse -Filter *.ps1
$badParse = 0
foreach ($f in $psFiles) {
    $t = $null; $e = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$t, [ref]$e)
    if ($e.Count) { Write-Host ("  [FAIL] {0}: {1}" -f $f.Name, $e[0].Message) -ForegroundColor Red; $badParse++ }
}
if ($badParse) { $fails++; Write-Host "  $badParse file(s) failed to parse" -ForegroundColor Red }
else { Write-Host ("  [PASS] {0} scripts parse cleanly" -f $psFiles.Count) -ForegroundColor Green }

# 2. Build ----------------------------------------------------------------------
Section '2/5 Build analyzer (Debug)'
& $dotnet build $proj -c Debug -v q --nologo
if ($LASTEXITCODE -ne 0) { $fails++; Write-Host '  [FAIL] build' -ForegroundColor Red }
else { Write-Host '  [PASS] build' -ForegroundColor Green }

# 3. Collector modules ----------------------------------------------------------
Section '3/5 Test-Modules'
& (Join-Path $PSScriptRoot 'Test-Modules.ps1')
if ($LASTEXITCODE -ne 0) { $fails++ }

# 4. Raw parsers (synthetic build -> import -> assert) --------------------------
Section '4/5 Raw parsers (synthetic)'
if (Test-Path $dll) {
    $tmp = Join-Path $env:TEMP ("hawk_rawci_" + [guid]::NewGuid().ToString('N').Substring(0,6))
    New-Item -ItemType Directory -Force $tmp | Out-Null
    & (Join-Path $PSScriptRoot 'Test-RawParsers.ps1') -OutDir $tmp | Out-Null
    $sess = Join-Path $tmp 'RAWTEST-001.hawk'
    if (Test-Path $sess) {
        $out = (& $dotnet exec $dll import $sess 2>&1 | Out-String)
        foreach ($p in 'prefetch','shimcache','amcache') {
            $m = [regex]::Match($out, "parsed $p`: (\d+) records")
            if ($m.Success -and [int]$m.Groups[1].Value -gt 0) {
                Write-Host ("  [PASS] {0} parser: {1} records" -f $p, $m.Groups[1].Value) -ForegroundColor Green
            } else {
                Write-Host ("  [FAIL] {0} parser produced 0 records" -f $p) -ForegroundColor Red; $fails++
            }
        }
    } else { Write-Host '  [FAIL] synthetic raw session not built' -ForegroundColor Red; $fails++ }
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
} else { Write-Host '  [SKIP] analyzer not built' -ForegroundColor Yellow; $fails++ }

# 5. End-to-end self-test -------------------------------------------------------
Section '5/5 Test-HawkSelfTest'
& (Join-Path $PSScriptRoot 'Test-HawkSelfTest.ps1')
if ($LASTEXITCODE -ne 0) { $fails++ }

Write-Host ("`n=== RESULT: {0} ===" -f $(if ($fails) { "$fails gate(s) FAILED" } else { 'ALL GREEN' })) -ForegroundColor ($(if ($fails) { 'Red' } else { 'Green' }))
exit $fails
