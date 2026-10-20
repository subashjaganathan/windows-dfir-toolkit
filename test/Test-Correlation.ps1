<#
.SYNOPSIS
    Correlation-engine test: synthetic evidence with one attack chain per rule PLUS
    benign look-alikes that must NOT fire. Exit code = number of failed assertions.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Continue'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("dfir_corr_" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force $tmp | Out-Null
$fail = 0
function Assert($name, [bool]$ok, $detail = '') {
    if ($ok) { Write-Host "  [PASS] $name" -ForegroundColor Green } else { Write-Host "  [FAIL] $name $detail" -ForegroundColor Red; $script:fail++ }
}
function Put($type, $obj) {
    $obj | Add-Member -NotePropertyName ArtifactType -NotePropertyValue $type -Force
    $obj | Add-Member -NotePropertyName ChainOfCustody -NotePropertyValue ([pscustomobject]@{ Hostname = 'TESTHOST'; ToolVersion = '1.1' }) -Force
    $obj | ConvertTo-Json -Depth 8 | Out-File (Join-Path $tmp "$type`_TESTHOST_20260101_000000.json") -Encoding UTF8
}
function P($procId, $name, $path, $ppid, $cmd, $sig = 'Valid', $owner = 'CORP\svc', $start = '2026-06-01T10:00:00Z') {
    [pscustomobject]@{ PID = $procId; ProcessName = $name; ExecutablePath = $path; ParentPID = $ppid; ParentName = $null; ParentIsStale = $false
                       CommandLine = $cmd; SignatureStatus = $sig; Signer = $null; Owner = $owner; StartTime = $start }
}
function E($id, $t, $data, $summary = '') { [pscustomobject]@{ EventID = $id; TimeCreated = $t; Summary = $summary; EventData = [pscustomobject]$data } }

# processes: attack chains + benign look-alikes
Put 'RunningProcesses' ([pscustomobject]@{ Data = @(
    (P 100 'w3wp'     'C:\Windows\System32\inetsrv\w3wp.exe' 4 'w3wp.exe -ap DefaultAppPool')
    (P 101 'cmd'      'C:\Windows\System32\cmd.exe' 100 'cmd /c whoami')                                          # C1 web shell
    (P 200 'WINWORD'  'C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE' 4 'winword invoice.docm' 'Valid' 'CORP\jdoe')
    (P 201 'powershell' 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' 200 'powershell -w hidden -enc AAA' 'Valid' 'CORP\jdoe')   # C1 + C2
    (P 300 'updater'  'C:\Users\jdoe\AppData\Roaming\upd\updater.exe' 4 'updater.exe' 'NotSigned' 'CORP\jdoe')  # C2 + C3 + C4
    (P 400 'explorer' 'C:\Windows\explorer.exe' 4 'explorer.exe' 'Valid' 'CORP\alice')
    (P 401 'cmd'      'C:\Windows\System32\cmd.exe' 400 'cmd.exe' 'Valid' 'CORP\alice')                             # benign: explorer->cmd
    (P 500 'svchost'  'C:\Windows\System32\svchost.exe' 4 'svchost -k netsvcs')                                   # benign: signed, private IP
    (P 600 'agent'    'C:\Program Files\Vendor\agent.exe' 4 'agent.exe')                                          # benign: persisted, signed, Program Files
    (P 700 'cmd'      'C:\Windows\System32\cmd.exe' 4 'cmd /c net user' 'Valid' 'CORP\bob' '2026-06-01T12:10:00Z') # C7 (after bob's RDP logon)
    (P 800 'Teams'    'C:\Users\jdoe\AppData\Local\Microsoft\Teams\current\Teams.exe' 4 'Teams.exe' 'Valid' 'CORP\jdoe') # benign: signed per-user app
) })
Put 'NetworkConnections' ([pscustomobject]@{ Data = @(
    [pscustomobject]@{ PID = 201; ProcessName = 'powershell'; ProcessPath = ''; RemoteAddress = '203.0.113.50'; RemotePort = 443; State = 'Established' }
    [pscustomobject]@{ PID = 300; ProcessName = 'updater';    ProcessPath = ''; RemoteAddress = '198.51.100.7'; RemotePort = 8080; State = 'Established' }
    [pscustomobject]@{ PID = 500; ProcessName = 'svchost';    ProcessPath = ''; RemoteAddress = '10.0.0.5';     RemotePort = 445; State = 'Established' }
    [pscustomobject]@{ PID = 600; ProcessName = 'agent';      ProcessPath = ''; RemoteAddress = '203.0.113.9';  RemotePort = 443; State = 'Established' }
    [pscustomobject]@{ PID = 800; ProcessName = 'Teams';      ProcessPath = ''; RemoteAddress = '52.112.0.10';  RemotePort = 443; State = 'Established' }
) })
Put 'RegistryRunKeys' ([pscustomobject]@{ Data = @(
    [pscustomobject]@{ RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'; ValueName = 'upd'; Command = '"C:\Users\jdoe\AppData\Roaming\upd\updater.exe" /silent' }
) })
Put 'WindowsServices' ([pscustomobject]@{ Data = @(
    [pscustomobject]@{ ServiceName = 'VendorAgent'; BinaryPath = '"C:\Program Files\Vendor\agent.exe"'; ExecutablePath = 'C:\Program Files\Vendor\agent.exe'; SignatureStatus = 'Valid' }
) })
Put 'FileSystemArtifacts' ([pscustomobject]@{ ZoneIdentifiers = @(
    [pscustomobject]@{ FilePath = 'C:\Users\jdoe\AppData\Roaming\upd\updater.exe'; ZoneID = '3'; ZoneLabel = 'Internet'; ReferrerUrl = ''; HostUrl = 'https://evil.example/updater.exe' }
) })
$ev = @()
1..8 | ForEach-Object { $ev += E 4625 ("2026-06-01T09:0{0}:00Z" -f $_) @{ IpAddress = '203.0.113.66'; TargetUserName = "admin$_"; LogonType = '3' } }
$ev += E 4624 '2026-06-01T09:20:00Z' @{ IpAddress = '203.0.113.66'; TargetUserName = 'svc_backup'; LogonType = '3' } 'Logon CORP\svc_backup (type 3) from 203.0.113.66'   # C5
1..8 | ForEach-Object { $ev += E 4625 ("2026-06-01T08:0{0}:00Z" -f $_) @{ IpAddress = '10.1.1.1'; TargetUserName = 'carol'; LogonType = '3' } }  # benign: no success
$ev += E 4720 '2026-06-01T11:00:00Z' @{ TargetUserName = 'backdoor'; TargetSid = 'S-1-5-21-1-1009'; SubjectUserName = 'jdoe' } 'User Account Created: backdoor'
$ev += E 4732 '2026-06-01T11:05:00Z' @{ TargetUserName = 'Administrators'; MemberSid = 'S-1-5-21-1-1009'; SubjectUserName = 'jdoe' } 'added to Administrators'   # C6
$ev += E 4720 '2026-06-01T11:00:00Z' @{ TargetUserName = 'newhire'; TargetSid = 'S-1-5-21-1-1010'; SubjectUserName = 'hr' } 'User Account Created: newhire'
$ev += E 4732 '2026-06-01T11:05:00Z' @{ TargetUserName = 'Users'; MemberSid = 'S-1-5-21-1-1010'; SubjectUserName = 'hr' } 'added to Users'                    # benign
$ev += E 4624 '2026-06-01T12:00:00Z' @{ IpAddress = '10.9.9.9'; TargetUserName = 'bob'; LogonType = '10' } 'Logon CORP\bob (type 10 RemoteInteractive (RDP)) from 10.9.9.9'  # C7
Put 'SecurityEventLog' ([pscustomobject]@{ Data = $ev })

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'Scripts\Reporting\Correlation_Engine.ps1') -EvidencePath $tmp *> $null
$out = Get-ChildItem $tmp -Filter 'Correlation_Findings_*.json' | Where-Object { $_.Name -notlike '*.hash.json' } | Select-Object -First 1
Assert 'engine wrote Correlation_Findings JSON' ($null -ne $out)
$f = if ($out) { @((Get-Content $out.FullName -Raw | ConvertFrom-Json).Findings) } else { @() }
function Has($rule, $pattern) { @($f | Where-Object { $_.RuleId -eq $rule -and "$($_.Title) $($_.Summary)" -match $pattern }).Count -gt 0 }

Assert 'C1 web shell: w3wp -> cmd (CRITICAL)'          (@($f | Where-Object { $_.RuleId -eq 'C1' -and $_.Title -match 'w3wp' -and $_.Severity -eq 'CRITICAL' }).Count -eq 1)
Assert 'C1 malicious doc: winword -> powershell'        (Has 'C1' 'winword.*powershell')
Assert 'C2 powershell to public IP'                     (Has 'C2' 'powershell.*203\.0\.113\.50')
Assert 'C2 user-writable unsigned updater to public IP' (Has 'C2' 'updater.*198\.51\.100\.7')
Assert 'C3 updater running AND persisted (Run key)'     (Has 'C3' 'updater')
Assert 'C4 downloaded updater running and persisted'    (@($f | Where-Object { $_.RuleId -eq 'C4' -and $_.Title -match 'running and persisted' -and $_.Severity -eq 'HIGH' }).Count -eq 1)
Assert 'C5 failed logons then success (public -> CRITICAL)' (@($f | Where-Object { $_.RuleId -eq 'C5' -and $_.Title -match '203\.0\.113\.66' -and $_.Severity -eq 'CRITICAL' }).Count -eq 1)
Assert 'C6 backdoor created + Administrators'           (Has 'C6' 'backdoor.*Administrators')
Assert 'C7 RDP logon by bob then cmd'                   (Has 'C7' 'bob.*cmd')
# benign look-alikes
Assert 'no finding for explorer -> cmd'                 (-not (@($f | Where-Object { $_.RuleId -eq 'C1' -and $_.Title -match 'explorer' }).Count))
Assert 'no finding for signed svchost on private IP'    (-not (Has 'C2' 'svchost'))
Assert 'no finding for signed per-user app (Teams in AppData) online' (-not (Has 'C2' 'teams'))
Assert 'no finding for signed Program Files agent'      (-not (@($f | Where-Object { "$($_.Title)" -match 'agent' }).Count))
Assert 'no finding for failures without success (10.1.1.1)' (-not (Has 'C5' '10\.1\.1\.1'))
Assert 'no finding for newhire added to Users'          (-not (Has 'C6' 'newhire'))
Assert 'every finding carries evidence records'         (@($f | Where-Object { @($_.Evidence).Count -lt 1 }).Count -eq 0)

Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ("  correlation: {0} finding(s), {1}" -f $f.Count, $(if ($fail) { "$fail FAILED" } else { 'all assertions passed' })) -ForegroundColor ($(if ($fail) { 'Red' } else { 'Green' }))
exit $fail
