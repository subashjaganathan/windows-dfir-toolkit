<#
.SYNOPSIS
    One-command test runner for the Windows DFIR Toolkit (used by CI and locally).

.DESCRIPTION
    A dependency-free safety net for a collection-script toolkit. No admin, no
    network, no evidence collected - it validates that the toolkit is internally
    consistent and free of syntax errors before it ever touches a target host.

    Gates:
      1. Parse-lint            - every .ps1 (collection scripts + orchestrator)
                                 parses cleanly under the PowerShell tokenizer.
      2. Orchestrator integrity - every script path referenced by
                                 Run_IR_Collection.ps1's execution plan exists on
                                 disk (a dangling reference = a phase that reports
                                 "NOT FOUND" in the field). Orphan scripts (present
                                 but never wired into the runner) are reported.
      3. PSScriptAnalyzer      - Error-severity static analysis, if the module is
                                 available. Skipped (not failed) when absent.

    Exit code = number of failed gates (0 = all green).

.EXAMPLE
    .\test\Run-AllTests.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
$Root        = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$ScriptsRoot = Join-Path $Root 'Scripts'
$Orchestrator = Join-Path $Root 'Run_IR_Collection.ps1'
$fails = 0

function Section($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }

# ---------------------------------------------------------------------------
# 1/3  Parse-lint : every .ps1 must tokenize with zero parse errors.
# ---------------------------------------------------------------------------
Section '1/3 PowerShell parse-lint'
$psFiles = @(Get-ChildItem $Root -Recurse -Filter *.ps1 | Where-Object { $_.FullName -notmatch '\\\.git\\' })
$badParse = 0
foreach ($f in $psFiles) {
    $tokens = $null; $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errors)
    if ($errors -and $errors.Count) {
        $rel = $f.FullName.Substring($Root.Length).TrimStart('\')
        Write-Host ("  [FAIL] {0}: {1} (line {2})" -f $rel, $errors[0].Message, $errors[0].Extent.StartLineNumber) -ForegroundColor Red
        $badParse++
    }
}
if ($badParse) { $fails++; Write-Host "  $badParse file(s) failed to parse" -ForegroundColor Red }
else { Write-Host ("  [PASS] {0} scripts parse cleanly" -f $psFiles.Count) -ForegroundColor Green }

# ---------------------------------------------------------------------------
# 2/3  Orchestrator integrity : referenced scripts exist; report orphans.
# ---------------------------------------------------------------------------
Section '2/3 Orchestrator integrity'
if (-not (Test-Path $Orchestrator)) {
    Write-Host "  [FAIL] Run_IR_Collection.ps1 not found" -ForegroundColor Red; $fails++
} elseif (-not (Test-Path $ScriptsRoot)) {
    Write-Host "  [FAIL] Scripts\ folder not found" -ForegroundColor Red; $fails++
} else {
    # Valid top-level categories = the actual Scripts\ subfolders. We only treat a
    # "Category\Name" literal as a script reference when Category is a real folder,
    # which keeps unrelated strings out of the reference set.
    $categories = @(Get-ChildItem $ScriptsRoot -Directory | Select-Object -ExpandProperty Name)
    $catSet = @{}; foreach ($c in $categories) { $catSet[$c.ToLower()] = $true }

    # AST-extract every string literal in the orchestrator, then classify it as a
    # script reference by shape. This is robust against hashtable/Join-Path layout
    # changes (no regex over the source text).
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Orchestrator, [ref]$tokens, [ref]$errors)
    $strs = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true)

    $referenced = New-Object System.Collections.Generic.HashSet[string]
    foreach ($s in $strs) {
        $v = $s.Value
        if ([string]::IsNullOrWhiteSpace($v)) { continue }
        $rel = $null
        if ($v -match '^Scripts[\\/].+\.ps1$') {
            # Direct "Scripts\Category\Name.ps1" reference (correlation/report/etc.)
            $rel = ($v -replace '^Scripts[\\/]', '') -replace '\.ps1$', ''
        } elseif ($v -match '^[A-Za-z0-9_]+[\\/][A-Za-z0-9_]+$') {
            # "Category\Name" execution-plan entry
            $cat = ($v -split '[\\/]')[0]
            if ($catSet.ContainsKey($cat.ToLower())) { $rel = $v }
        }
        if ($rel) { [void]$referenced.Add(($rel -replace '/', '\')) }
    }

    $missing = @()
    foreach ($r in $referenced) {
        $path = Join-Path $ScriptsRoot ($r + '.ps1')
        if (-not (Test-Path $path)) { $missing += $r }
    }

    # Orphans: scripts on disk that the orchestrator never references (informational).
    $onDisk = @(Get-ChildItem $ScriptsRoot -Recurse -Filter *.ps1 | ForEach-Object {
        ($_.FullName.Substring($ScriptsRoot.Length).TrimStart('\')) -replace '\.ps1$', ''
    })
    $orphans = @($onDisk | Where-Object { -not $referenced.Contains($_) } | Sort-Object)

    if ($missing.Count) {
        $fails++
        Write-Host ("  [FAIL] {0} referenced script(s) missing from disk:" -f $missing.Count) -ForegroundColor Red
        foreach ($m in ($missing | Sort-Object)) { Write-Host "         Scripts\$m.ps1" -ForegroundColor Red }
    } else {
        Write-Host ("  [PASS] all {0} orchestrator-referenced scripts exist" -f $referenced.Count) -ForegroundColor Green
    }
    if ($orphans.Count) {
        Write-Host ("  [INFO] {0} script(s) present but not wired into the runner:" -f $orphans.Count) -ForegroundColor Yellow
        foreach ($o in $orphans) { Write-Host "         Scripts\$o.ps1" -ForegroundColor DarkYellow }
    }
}

# ---------------------------------------------------------------------------
# 3/3  PSScriptAnalyzer (Error severity) : optional, skipped if unavailable.
# ---------------------------------------------------------------------------
Section '3/3 PSScriptAnalyzer (Error severity)'
if (Get-Module -ListAvailable -Name PSScriptAnalyzer) {
    Import-Module PSScriptAnalyzer -ErrorAction SilentlyContinue
    $pssaErrors = @(Invoke-ScriptAnalyzer -Path $Root -Recurse -Severity Error -ErrorAction SilentlyContinue |
                    Where-Object { $_.ScriptPath -notmatch '\\\.git\\' })
    if ($pssaErrors.Count) {
        $fails++
        Write-Host ("  [FAIL] {0} Error-severity finding(s):" -f $pssaErrors.Count) -ForegroundColor Red
        foreach ($e in $pssaErrors) {
            $rel = $e.ScriptPath.Substring($Root.Length).TrimStart('\')
            Write-Host ("         {0}:{1} {2}" -f $rel, $e.Line, $e.RuleName) -ForegroundColor Red
        }
    } else {
        Write-Host "  [PASS] no Error-severity findings" -ForegroundColor Green
    }
} else {
    Write-Host "  [SKIP] PSScriptAnalyzer not installed" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
Write-Host ("`n=== RESULT: {0} ===" -f $(if ($fails) { "$fails gate(s) FAILED" } else { 'ALL GREEN' })) -ForegroundColor $(if ($fails) { 'Red' } else { 'Green' })
exit $fails
