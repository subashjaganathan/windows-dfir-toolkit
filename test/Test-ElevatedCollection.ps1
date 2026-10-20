<#
.SYNOPSIS
    REAL end-to-end collection on this host - requires Administrator.
    Runs in CI on GitHub's Windows runners (which are elevated); locally it skips
    unless run from an elevated prompt.

      1. Script path: Run_IR_Collection.ps1 -Phase EventLogs and -Phase Registry for
         real (Security .evtx, registry hives), move the evidence, Verify-Evidence.
      2. Exe path: Build-Exe.ps1, run dist\HawkWindowsCollector.exe non-interactively
         with an -OutputPath containing spaces; exit code, manifest, verification.
      3. Constrained Language Mode: orchestrator must refuse with exit 4.
    Exit code = number of failed assertions.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Continue'
$Root = Resolve-Path (Join-Path $PSScriptRoot '..')

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators')
if (-not $isAdmin) {
    if ($env:CI) { Write-Host '[FAIL] CI runner is not elevated' -ForegroundColor Red; exit 1 }
    Write-Host '[SKIP] Test-ElevatedCollection needs an elevated prompt (runs in CI).' -ForegroundColor Yellow; exit 0
}

$fail = 0
function Assert($name, [bool]$cond, $detail = '') {
    if ($cond) { Write-Host "  [PASS] $name" -ForegroundColor Green }
    else { Write-Host "  [FAIL] $name $detail" -ForegroundColor Red; $script:fail++ }
}
function Get-Manifest($dir) {
    Get-ChildItem $dir -Filter 'Evidence_Manifest_*.json' -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notlike '*.hash.json' } | Select-Object -First 1
}
function Test-Verify($manifest) {
    $o = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'Scripts\Reporting\Verify-Evidence.ps1') -ManifestPath $manifest 2>&1 | Out-String
    @{ Ok = ($LASTEXITCODE -eq 0 -and $o -match 'RESULT: VERIFIED'); Out = $o }
}

$work = Join-Path ([IO.Path]::GetPathRoot("$Root")) ("tk_elev_" + [guid]::NewGuid().ToString('N').Substring(0, 6))
New-Item -ItemType Directory -Force $work | Out-Null
$runner = Join-Path $Root 'Run_IR_Collection.ps1'

# --- 1. script path ------------------------------------------------------------------
foreach ($phase in 'EventLogs', 'Registry', 'FileSystem_Advanced', 'Execution', 'Network') {
    Write-Host "`n=== 1. Run_IR_Collection.ps1 -Phase $phase (elevated, real) ===" -ForegroundColor Cyan
    $out = Join-Path $work "out_$phase"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $runner -OutputPath $out -Phase $phase *> (Join-Path $work "$phase.log")
    $rc = $LASTEXITCODE
    Assert "$phase phase exit 0" ($rc -eq 0) "(exit $rc; log tail: $((Get-Content (Join-Path $work "$phase.log") -Tail 5) -join ' | '))"
    $m = Get-Manifest $out
    Assert "$phase manifest written" ($null -ne $m)
    Assert "$phase evidence package sealed" (@(Get-ChildItem $out -Filter 'Evidence_Package_*.zip' -ErrorAction SilentlyContinue).Count -eq 1)
    if ($phase -eq 'EventLogs') {
        $j = Get-ChildItem $out -Filter 'EventLogs_Raw_*.json' | Where-Object { $_.Name -notlike '*.hash.json' } | Select-Object -First 1
        $sec = if ($j) { (Get-Content $j.FullName -Raw | ConvertFrom-Json).ExportResults | Where-Object { $_.LogName -eq 'Security' } }
        Assert 'Security.evtx exported (in-process API)' ($sec -and $sec.CopyStatus -eq 'Success' -and $sec.SHA256) "($($sec.CopyStatus))"
        Assert 'raw EVTX snapshot ran FIRST in the phase' ((Select-String -Path (Join-Path $work "$phase.log") -Pattern 'Phase: EventLogs_Raw' -SimpleMatch | Select-Object -First 1).LineNumber -lt
            (Select-String -Path (Join-Path $work "$phase.log") -Pattern 'Running: Security_EventLog' -SimpleMatch | Select-Object -First 1).LineNumber)
    }
    if ($phase -eq 'Registry') {
        $j = Get-ChildItem $out -Filter 'Registry_Hive_Export_*.json' | Where-Object { $_.Name -notlike '*.hash.json' } | Select-Object -First 1
        $r = if ($j) { Get-Content $j.FullName -Raw | ConvertFrom-Json }
        $sys = if ($r) { $r.Results | Where-Object { $_.HiveName -eq 'SYSTEM' } }
        Assert 'SYSTEM hive is a RAW VSS copy (not reg save re-serialized)' ($sys -and $sys.Exported -and $sys.Method -like 'VSS*') "($($sys.Method))"
        Assert 'SYSTEM hive transaction logs (.LOG1/.LOG2) collected' (@($sys.TransactionLogs).Count -ge 1) "($(@($sys.TransactionLogs).Count))"
        Assert 'Amcache.hve acquired' (@($r.Results | Where-Object { $_.HiveName -eq 'Amcache.hve' -and $_.Exported }).Count -eq 1)
        Assert 'at least one NTUSER.DAT acquired' (@($r.Results | Where-Object { $_.HiveName -like 'NTUSER.DAT*' -and $_.Exported }).Count -ge 1)
    }
    if ($phase -eq 'FileSystem_Advanced') {
        $j = Get-ChildItem $out -Filter 'MFT_USN_*.json' | Where-Object { $_.Name -notlike '*.hash.json' } | Select-Object -First 1
        $c = if ($j) { (Get-Content $j.FullName -Raw | ConvertFrom-Json).VolumeResults | Where-Object { $_.Drive -eq $env:SystemDrive } }
        Assert 'raw $MFT extracted from the system volume' ($c -and $c.MFTCopied -and $c.MFTSizeBytes -gt 1MB) "($($c.Error))"
        Assert 'raw $LogFile extracted' ($c -and $c.LogFileCopied) "($($c.Error))"
        $mftFile = if ($c) { $c.MFTPath }
        if ($mftFile -and (Test-Path $mftFile)) {
            $fs = [IO.File]::OpenRead($mftFile); $sig = New-Object byte[] 4; [void]$fs.Read($sig, 0, 4); $fs.Close()
            Assert '$MFT starts with a FILE record' ([Text.Encoding]::ASCII.GetString($sig) -eq 'FILE')
        }
    }
    if ($phase -eq 'FileSystem_Advanced' -or $phase -eq 'Registry') {
        Assert "$phase removed the shadow copy it created" ((Select-String -Path (Join-Path $work "$phase.log") -Pattern 'Removed \d+ shadow copy' -Quiet) -and
            -not (Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue | Where-Object { $_.InstallDate -gt (Get-Date).AddMinutes(-30) }))
    }
    if ($phase -eq 'Execution') {
        $j = Get-ChildItem $out -Filter 'Running_Processes_*.json' | Where-Object { $_.Name -notlike '*.hash.json' } | Select-Object -First 1
        $p = if ($j) { @((Get-Content $j.FullName -Raw | ConvertFrom-Json).Data) } else { @() }
        Assert 'processes carry command lines (WMI join)' (@($p | Where-Object CommandLine).Count -gt ($p.Count / 2)) "($(@($p | Where-Object CommandLine).Count)/$($p.Count))"
        Assert 'protected processes keep an image path (lsass)' (@($p | Where-Object { $_.ProcessName -eq 'lsass' -and $_.ExecutablePath -like '*lsass.exe' }).Count -eq 1)
    }
    if ($phase -eq 'Network') {
        $j = Get-ChildItem $out -Filter 'Network_Connections_*.json' | Where-Object { $_.Name -notlike '*.hash.json' } | Select-Object -First 1
        $n = if ($j) { @((Get-Content $j.FullName -Raw | ConvertFrom-Json).Data) } else { @() }
        Assert 'connections attributed to processes (not Unknown)' ($n.Count -and @($n | Where-Object { $_.ProcessName -ne 'Unknown' }).Count -eq $n.Count) "($(@($n | Where-Object { $_.ProcessName -ne 'Unknown' }).Count)/$($n.Count))"
    }
    if ($phase -eq 'EventLogs') {
        $j = Get-ChildItem $out -Filter 'Security_EventLog_*.json' | Where-Object { $_.Name -notlike '*.hash.json' } | Select-Object -First 1
        $s = if ($j) { @((Get-Content $j.FullName -Raw | ConvertFrom-Json).Data | Where-Object { $_.EventID -eq 4624 }) } else { @() }
        Assert '4624 logons parsed with structured fields (TargetUserName, LogonType)' ($s.Count -and $s[0].EventData.TargetUserName -and $s[0].EventData.LogonType) "($($s.Count) events)"
    }
    if ($m) {
        $moved = Join-Path $work "moved_$phase"
        Move-Item $out $moved
        $v = Test-Verify (Get-Manifest $moved).FullName
        Assert "$phase evidence VERIFIED after moving it (custody transfer)" $v.Ok "($(($v.Out -split "`n" | Select-String 'RESULT|MISSING|MISMATCH' | Select-Object -First 3) -join ' | '))"
    }
}

# --- 2. exe path -------------------------------------------------------------------
Write-Host "`n=== 2. HawkWindowsCollector.exe (non-interactive) ===" -ForegroundColor Cyan
Push-Location $Root
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'Build\Build-Exe.ps1') -NoSign | Out-Null
Pop-Location
$exe = Join-Path $Root 'dist\HawkWindowsCollector.exe'
Assert 'exe built' (Test-Path $exe)
$exeDir = Join-Path $work 'usb'; New-Item -ItemType Directory -Force $exeDir | Out-Null
Copy-Item $exe $exeDir
$out2 = Join-Path $work 'out exe with spaces'
$p = Start-Process -FilePath (Join-Path $exeDir 'HawkWindowsCollector.exe') -ArgumentList @('-OutputPath', "`"$out2`"", '-Phase', 'Network') -Wait -PassThru -NoNewWindow
Assert 'exe exit 0 (orchestrator code passed through)' ($p.ExitCode -eq 0) "(exit $($p.ExitCode))"
$m2 = Get-Manifest $out2
Assert 'exe: manifest in -OutputPath (path with spaces)' ($null -ne $m2)
Assert 'exe: extracted toolkit removed afterwards' (@(Get-ChildItem $exeDir -Directory -Filter 'DFIR_Toolkit_*').Count -eq 0)
if ($m2) { $v = Test-Verify $m2.FullName; Assert 'exe: evidence VERIFIED' $v.Ok }

# --- 3. Constrained Language Mode --------------------------------------------------------
Write-Host "`n=== 3. Constrained Language Mode refusal ===" -ForegroundColor Cyan
$out3 = Join-Path $work 'out_clm'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "`$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'; & '$runner' -OutputPath '$out3' -Phase Network; exit `$LASTEXITCODE" *> $null
Assert 'CLM: exit 4' ($LASTEXITCODE -eq 4) "(exit $LASTEXITCODE)"
Assert 'CLM: nothing written' (-not (Test-Path $out3))

Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ("`n=== elevated collection: {0} ===" -f $(if ($fail) { "$fail FAILED" } else { 'ALL PASS' })) -ForegroundColor ($(if ($fail) { 'Red' } else { 'Green' }))
exit $fail
