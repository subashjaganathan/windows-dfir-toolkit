<#
.SYNOPSIS
    Collector module regression guard. Parses AND executes every collection
    module against the LOCAL machine (read-only, no admin required) and asserts
    each one loads, runs, and writes a valid artifact envelope.

    This catches the class of bug the synthetic session test cannot: modules
    that only fail when actually executed (StrictMode quirks, bad hashtable
    literals, unguarded Test-Path on ACL'd paths, etc.).
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Continue'
$Suite = Resolve-Path (Join-Path $PSScriptRoot '..')
Import-Module (Join-Path $Suite 'Collector\Runtime\Hawk.Common.psm1') -Force

$work = Join-Path $env:TEMP "hawk_modtest_$(Get-Date -Format yyyyMMddHHmmss)"
Initialize-HawkSession -WorkRoot $work | Out-Null
$cfg = [pscustomobject]@{ eventLogDays = 30 }

$ok = 0; $fail = 0
Get-ChildItem (Join-Path $Suite 'Collector\Modules') -Recurse -Filter *.ps1 |
    Sort-Object FullName | ForEach-Object {
    $name = $_.BaseName
    $t = $null; $e = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$t, [ref]$e)
    if ($e.Count) {
        Write-Host ("  [FAIL] {0,-22} parse: {1}" -f $name, $e[0].Message) -ForegroundColor Red; $script:fail++; return
    }
    try {
        $count = & $_.FullName -SessionRoot $work -Config $cfg
        $artifact = Join-Path $work "artifacts\$name.json"
        if (-not (Test-Path $artifact)) { throw "no artifact written" }
        # validate envelope shape the importer relies on
        $env = Get-Content $artifact -Raw | ConvertFrom-Json
        if (-not $env.PSObject.Properties.Name.Contains('records')) { throw "envelope missing 'records'" }
        Write-Host ("  [PASS] {0,-22} {1} records" -f $name, $count) -ForegroundColor Green; $script:ok++
    } catch {
        Write-Host ("  [FAIL] {0,-22} run: {1}" -f $name, $_.Exception.Message) -ForegroundColor Red; $script:fail++
    }
}
Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "`n=== $ok passed, $fail failed ===" -ForegroundColor ($(if ($fail) {'Red'} else {'Green'}))
exit $fail
