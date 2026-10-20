<#
.SYNOPSIS
    Evidence-quality gate: audits collected evidence JSON for SILENT data loss.

.DESCRIPTION
    The bugs fixed in v1.1 produced no error at all - command lines, parent PIDs and
    connection owners were simply empty in every record, Security events were cut
    short, Mark-of-the-Web values came from the wrong file. Unit-style tests did
    not notice because the scripts "succeeded". This gate inspects real output:

      Universal (every artifact JSON):
        - parses as JSON and carries ChainOfCustody with the current ToolVersion
        - no "\/Date(ms)\/" timestamps (raw DateTime under Windows PowerShell 5.1)
        - no objects flattened to strings ("System.Object[]", "@{Name=...}")
        - no leaked ETS provider metadata (PSProvider/PSPath) - a serialized
          Get-Content line drags in the whole provider/type graph
      Critical fields (only when the artifact has enough records to judge):
        - Running_Processes : CommandLine / ParentPID / ExecutablePath not empty everywhere
        - Network_Connections: connections attributed to a process (not all "Unknown")
        - Security_EventLog  : every event has a Summary; structured EventData present
        - FileSystem_Artifacts: every Zone.Identifier record has a ZoneID
        - Registry_Hive_Export: elevated runs must use raw VSS copies, not reg save

    Exit code = number of failed checks. Used by Run-AllTests (gate 5) and by
    Test-ElevatedCollection on every phase it runs.

.PARAMETER EvidencePath
    Folder containing collected *.json artifacts (Run_IR_Collection -OutputPath).
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$EvidencePath, [switch]$Quiet)

$ErrorActionPreference = 'Continue'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$Expected = (Select-String -Path (Join-Path $Root 'Scripts\Infrastructure\DFIR_Common.psm1') `
    -Pattern '^\$Global:DFIR_ToolVersion\s*=\s*"([^"]+)"').Matches[0].Groups[1].Value
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators')

$fail = 0
function Check($name, [bool]$ok, $detail = '') {
    if ($ok) { if (-not $Quiet) { Write-Host "  [PASS] $name" -ForegroundColor Green } }
    else { Write-Host "  [FAIL] $name $detail" -ForegroundColor Red; $script:fail++ }
}
function Records($obj, [string]$prop) { if ($obj -and $obj.PSObject.Properties[$prop]) { @($obj.$prop | Where-Object { $_ }) } else { @() } }
function Share($recs, [scriptblock]$pred) { if (-not $recs.Count) { return 1.0 }; @($recs | Where-Object $pred).Count / $recs.Count }

$files = @(Get-ChildItem $EvidencePath -Filter '*.json' -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notlike '*.hash.json' -and $_.Name -notlike 'Evidence_Manifest_*' -and $_.Name -notlike 'Evidence_Package_*' -and $_.Name -notlike 'Collector_Footprint_*' })
Check "evidence JSON present in $EvidencePath" ($files.Count -gt 0)
$parsed = @{}

foreach ($f in $files) {
    $raw = [IO.File]::ReadAllText($f.FullName)
    $type = ($f.BaseName -replace "_$([regex]::Escape($env:COMPUTERNAME))_\d{8}_\d{6}$", '')
    $j = $null
    try { $j = $raw | ConvertFrom-Json -ErrorAction Stop } catch {}
    Check "$type parses as JSON" ($null -ne $j)
    if (-not $j) { continue }
    $parsed[$type] = $j
    $coc = if ($j.PSObject.Properties['ChainOfCustody']) { $j.ChainOfCustody } else { $null }
    Check "$type has ChainOfCustody with ToolVersion $Expected" ($coc -and "$($coc.ToolVersion)" -eq $Expected) "(got '$($coc.ToolVersion)')"
    Check "$type has no \/Date()\/ timestamps" ($raw -notmatch '\\/Date\(-?\d+')
    # A type name where a value should be ("System.Object[]", "@{Name=...}"); DLL/EXE file
    # names such as "System.Collections.dll" are legitimate values and excluded.
    $flat = [regex]::Match($raw, '"(System\.Object\[\]|System\.Collections\.[A-Za-z.`0-9\[\]]+(?<!\.dll)(?<!\.exe)|@\{[A-Za-z_]+=[^"]{0,40})"')
    Check "$type has no objects flattened to strings" (-not $flat.Success) "($($flat.Value))"
    # Get-Content lines carry ETS note properties; serialized, each drags in the whole
    # PSProvider/type graph (a 1 KB hosts file became 21 MB of evidence).
    Check "$type has no leaked ETS provider metadata (PSProvider/PSPath)" ($raw -notmatch '"PSProvider"\s*:') "($([regex]::Matches($raw, '"PSProvider"\s*:').Count) occurrences)"
}

# --- critical fields -------------------------------------------------------------
if ($parsed['Running_Processes']) {
    $p = Records $parsed['Running_Processes'] 'Data'
    if ($p.Count -ge 5) {
        Check 'Running_Processes: CommandLine present (WMI join works)' ((Share $p { $_.CommandLine }) -gt 0.2) ("({0:P0})" -f (Share $p { $_.CommandLine }))
        Check 'Running_Processes: ParentPID present' ((Share $p { $null -ne $_.ParentPID }) -gt 0.9) ("({0:P0})" -f (Share $p { $null -ne $_.ParentPID }))
        Check 'Running_Processes: ExecutablePath present' ((Share $p { $_.ExecutablePath }) -gt 0.2)
        if ($IsAdmin) { Check 'Running_Processes: lsass keeps its image path (admin)' (@($p | Where-Object { $_.ProcessName -eq 'lsass' -and $_.ExecutablePath }).Count -eq 1) }
    }
}
if ($parsed['Network_Connections']) {
    $n = Records $parsed['Network_Connections'] 'Data'
    if ($n.Count -ge 5) {
        Check 'Network_Connections: attributed to processes' ((Share $n { $_.ProcessName -and $_.ProcessName -ne 'Unknown' }) -gt 0.9) ("({0:P0})" -f (Share $n { $_.ProcessName -ne 'Unknown' }))
    }
}
if ($parsed['Security_EventLog']) {
    $s = Records $parsed['Security_EventLog'] 'Data'
    if ($s.Count) {
        Check 'Security_EventLog: every event has a Summary' ((Share $s { $_.Summary }) -eq 1)
        Check 'Security_EventLog: structured EventData extracted' ((Share $s { $_.EventData -and @($_.EventData.PSObject.Properties).Count }) -gt 0.5)
        $l = @($s | Where-Object { $_.EventID -eq 4624 })
        if ($l.Count) { Check 'Security_EventLog: 4624 carries TargetUserName + LogonType' ((Share $l { $_.EventData.TargetUserName -and $_.EventData.LogonType }) -gt 0.9) }
    }
}
if ($parsed['FileSystem_Artifacts']) {
    $z = Records $parsed['FileSystem_Artifacts'] 'ZoneIdentifiers'
    if ($z.Count) { Check 'FileSystem_Artifacts: every Zone.Identifier has a ZoneID' ((Share $z { "$($_.ZoneID)" -match '^\d$' }) -eq 1) }
}
if ($parsed['Registry_Hive_Export'] -and $IsAdmin) {
    $h = Records $parsed['Registry_Hive_Export'] 'Results'
    $sys = $h | Where-Object { $_.HiveName -eq 'SYSTEM' }
    Check 'Registry_Hive_Export: SYSTEM is a raw VSS copy (admin)' ($sys -and $sys.Method -like 'VSS*') "($($sys.Method))"
}

if (-not $Quiet -or $fail) { Write-Host ("  evidence quality: {0} artifact(s), {1}" -f $files.Count, $(if ($fail) { "$fail FAILED" } else { 'all checks passed' })) -ForegroundColor ($(if ($fail) { 'Red' } else { 'Green' })) }
exit $fail
