#Requires -Version 5.1
<#
.SYNOPSIS
    Correlation engine - joins collected artifacts into attack CHAINS.

.DESCRIPTION
    The report's per-artifact checks flag single signals (an unsigned DLL, an
    encoded task). Real intrusions show up as converging signals across sources:
    a web server spawns cmd.exe, a downloaded binary is both running and
    persisted, failed logons from one IP are followed by a success from it.
    Every rule here joins at least two independent artifacts, so findings are
    corroborated rather than keyword hits, and each finding carries the
    evidence records it was built from.

      C1 Process lineage        server / Office parent -> shell or LOLBin child
                                (live process tree + Security 4688 history)
      C2 Process <-> network    LOLBin / unsigned / user-writable binary talking to a PUBLIC IP
      C3 Process <-> persistence binary running AND persisted, from a user-writable path or unsigned
      C4 MOTW <-> execution     Internet-zone (downloaded) file running or persisted
      C5 Logon sequence         failed logons from an IP followed by a SUCCESS from that IP
      C6 Account abuse          account created and added to a privileged group within 24 h
      C7 Remote logon <-> exec  remote logon, then that user runs a shell/LOLBin within 30 min

    Output: Correlation_Findings_<host>_<ts>.json (ArtifactType CorrelationFindings),
    read by Generate_IR_Report.ps1. Runs offline on collected evidence only.

.IR_PHASE
    Analysis / Reporting

.AUTHOR
    Subash J

.VERSION
    1.1
#>
param([string]$EvidencePath = "")

Set-StrictMode -Off
$ErrorActionPreference = "Continue"

$__DFIRMod = Join-Path $PSScriptRoot '..\Infrastructure\DFIR_Common.psm1'
if (Test-Path $__DFIRMod) { Import-Module $__DFIRMod -Force -ErrorAction SilentlyContinue }
if (-not $Global:DFIR_ToolVersion) { $Global:DFIR_ToolVersion = '1.1' }

$BasePath = if ($EvidencePath) { $EvidencePath } elseif ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum  = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
$Stamp    = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile  = Join-Path $BasePath "Correlation_Engine_Execution.log"
function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }

# --- load evidence (latest file per ArtifactType) ------------------------------------
$Evidence = @{}
$HostName = $env:COMPUTERNAME
foreach ($f in @(Get-ChildItem $BasePath -Filter '*.json' -File -ErrorAction SilentlyContinue |
                 Where-Object { $_.Name -notmatch '\.hash\.json$|^Evidence_|^Correlation_Findings_|^IR_Report|^Collector_Footprint_' } |
                 Sort-Object LastWriteTime)) {
    try {
        $j = [IO.File]::ReadAllText($f.FullName) | ConvertFrom-Json -ErrorAction Stop
        if ($j.ArtifactType) {
            $Evidence[$j.ArtifactType] = $j
            if ($j.ChainOfCustody -and $j.ChainOfCustody.Hostname) { $HostName = $j.ChainOfCustody.Hostname }
        }
    } catch {}
}
Write-Log "Correlation started | evidence types loaded: $($Evidence.Count)"
function Rows($type, $prop = 'Data') { $e = $Evidence[$type]; if ($e -and $e.PSObject.Properties[$prop]) { @($e.$prop | Where-Object { $_ }) } else { @() } }

# --- helpers ------------------------------------------------------------------------
$Shells  = 'cmd.exe','powershell.exe','pwsh.exe','wscript.exe','cscript.exe','mshta.exe','rundll32.exe','regsvr32.exe',
           'certutil.exe','bitsadmin.exe','msbuild.exe','installutil.exe','wmic.exe','msiexec.exe','hh.exe','forfiles.exe'
$Servers = 'w3wp.exe','httpd.exe','nginx.exe','tomcat.exe','tomcat9.exe','sqlservr.exe','java.exe','php-cgi.exe','umworkerprocess.exe','exchange.exe'
$Office  = 'winword.exe','excel.exe','powerpnt.exe','outlook.exe','onenote.exe','mspub.exe','msaccess.exe','visio.exe','acrord32.exe','acrobat.exe'
$UserWritable = '\\appdata\\','\\temp\\','\\downloads\\','\\users\\public\\','\\programdata\\','\\perflogs\\','\\windows\\tasks\\','\$recycle\.bin','\\desktop\\'

function Leaf([string]$p) { if (-not $p) { return '' }; $x = $p.Trim('"', ' ').Replace('/', '\'); ($x.Substring($x.LastIndexOf('\') + 1)).ToLowerInvariant() }
function Norm([string]$p) { if (-not $p) { return '' }; ([Environment]::ExpandEnvironmentVariables($p.Trim('"', ' '))).ToLowerInvariant() }
function Exe([string]$cmd) {
    # executable path from a command line / service ImagePath / task action
    if (-not $cmd) { return '' }
    $c = [Environment]::ExpandEnvironmentVariables($cmd.Trim())
    if ($c.StartsWith('"')) { $e = $c.IndexOf('"', 1); if ($e -gt 1) { return $c.Substring(1, $e - 1).ToLowerInvariant() } }
    $m = [regex]::Match($c, '^(.+?\.(exe|dll|com|bat|cmd|ps1|vbs|js|hta|scr))(\s|,|$)', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value.ToLowerInvariant() }
    ($c -split '\s+')[0].ToLowerInvariant()
}
function UserWritable([string]$p) { $n = Norm $p; if (-not $n) { return $false }; foreach ($u in $UserWritable) { if ($n -match $u) { return $true } }; $false }
function Unsigned($sig) { "$sig" -in 'NotSigned','HashMismatch','NotTrusted','UnknownError' }
function IsPublic([string]$ip) {
    if (-not $ip -or $ip -in '0.0.0.0','::','127.0.0.1','::1','-') { return $false }
    $a = $null; if (-not [Net.IPAddress]::TryParse($ip.Trim(), [ref]$a)) { return $false }
    if ($a.IsIPv4MappedToIPv6) { $a = $a.MapToIPv4() }
    if ([Net.IPAddress]::IsLoopback($a)) { return $false }
    $b = $a.GetAddressBytes()
    if ($b.Length -eq 4) {
        return -not ($b[0] -eq 10 -or ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or ($b[0] -eq 192 -and $b[1] -eq 168) -or
                     ($b[0] -eq 169 -and $b[1] -eq 254) -or ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) -or $b[0] -ge 224 -or $b[0] -eq 0)
    }
    -not ($a.IsIPv6LinkLocal -or $a.IsIPv6SiteLocal -or $a.IsIPv6Multicast -or ($b[0] -band 0xFE) -eq 0xFC)
}
function ToUtc($t) { if (-not $t) { return $null }; try { ([datetime]::Parse("$t", [Globalization.CultureInfo]::InvariantCulture, 'AdjustToUniversal,AssumeUniversal')) } catch { $null } }

$Findings = [System.Collections.Generic.List[object]]::new()
$Seen = @{}
function Add-Finding {
    param([string]$Rule, [string]$Key, [string]$Title, [ValidateSet('CRITICAL','HIGH','MEDIUM')][string]$Severity,
          [string]$Confidence, [string[]]$MITRE, [string]$Summary, [object[]]$Evidence, $When = $null)
    if ($Seen.ContainsKey("$Rule|$Key")) { return }
    $Seen["$Rule|$Key"] = $true
    $Findings.Add([PSCustomObject]@{
        RuleId = $Rule; Title = $Title; Severity = $Severity; Confidence = $Confidence; MITRE = $MITRE
        Summary = $Summary; FirstSeenUtc = if ($When) { (ToUtc $When).ToString('o') } else { $null }
        Evidence = @($Evidence)
    })
}
function Ev($artifact, $detail) { [PSCustomObject]@{ Artifact = $artifact; Detail = "$detail" } }

# --- inputs --------------------------------------------------------------------------
$Procs   = Rows 'RunningProcesses'
$Conns   = Rows 'NetworkConnections'
$SecEvts = Rows 'SecurityEventLog'
$Zone    = Rows 'FileSystemArtifacts' 'ZoneIdentifiers'
$Persist = [System.Collections.Generic.List[object]]::new()
foreach ($r in Rows 'RegistryRunKeys')  { $Persist.Add([PSCustomObject]@{ Kind = 'Run key';        Name = "$($r.RegistryPath)\$($r.ValueName)"; Path = Exe $r.Command; Raw = $r.Command }) }
foreach ($r in Rows 'ScheduledTasks')   { $Persist.Add([PSCustomObject]@{ Kind = 'Scheduled task'; Name = "$($r.TaskPath)$($r.TaskName)"; Path = Exe $r.Command; Raw = "$($r.Command) $($r.Arguments)".Trim() }) }
foreach ($r in Rows 'WindowsServices')  { $Persist.Add([PSCustomObject]@{ Kind = 'Service';        Name = $r.ServiceName; Path = $(if ($r.ExecutablePath) { Norm $r.ExecutablePath } else { Exe $r.BinaryPath }); Raw = $r.BinaryPath; Sig = $r.SignatureStatus }) }
foreach ($r in Rows 'StartupFolder')    { $Persist.Add([PSCustomObject]@{ Kind = 'Startup folder'; Name = $r.FullPath; Path = $(if ($r.TargetPath) { Norm $r.TargetPath } else { Norm $r.FullPath }); Raw = "$($r.TargetPath) $($r.LnkArguments)".Trim() }) }
$Inputs = [ordered]@{
    RunningProcesses = $Procs.Count; NetworkConnections = $Conns.Count; SecurityEvents = $SecEvts.Count
    ZoneIdentifiers = $Zone.Count; PersistenceEntries = $Persist.Count
}
Write-Log ("inputs: " + (($Inputs.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ' '))

$ProcByPid = @{}; foreach ($p in $Procs) { if ($null -ne $p.PID) { $ProcByPid[[int]$p.PID] = $p } }
$ProcPaths = @{}; foreach ($p in $Procs) { $n = Norm $p.ExecutablePath; if ($n) { $ProcPaths[$n] = $p } }
$PersistByPath = @{}; foreach ($x in $Persist) { if ($x.Path) { if (-not $PersistByPath[$x.Path]) { $PersistByPath[$x.Path] = @() }; $PersistByPath[$x.Path] += $x } }

# --- C1 process lineage ----------------------------------------------------------------
$lineage = @()
foreach ($p in $Procs) {
    $par = if ($null -ne $p.ParentPID -and -not $p.ParentIsStale) { $ProcByPid[[int]$p.ParentPID] } else { $null }
    $lineage += [PSCustomObject]@{ Child = Leaf $(if ($p.ExecutablePath) { $p.ExecutablePath } else { "$($p.ProcessName).exe" }); Parent = $(if ($par) { Leaf $(if ($par.ExecutablePath) { $par.ExecutablePath } else { "$($par.ProcessName).exe" }) } else { (Leaf "$($p.ParentName)") });
                                   Cmd = $p.CommandLine; Pid = $p.PID; When = $p.StartTime; Src = 'RunningProcesses' }
}
foreach ($e in ($SecEvts | Where-Object { $_.EventID -eq 4688 })) {
    $lineage += [PSCustomObject]@{ Child = Leaf $e.EventData.NewProcessName; Parent = Leaf $e.EventData.ParentProcessName
                                   Cmd = $e.EventData.CommandLine; Pid = $e.EventData.NewProcessId; When = $e.TimeCreated; Src = 'Security 4688' }
}
foreach ($l in $lineage) {
    if ($l.Child -notin $Shells) { continue }
    if ($l.Parent -in $Servers) {
        Add-Finding 'C1' "$($l.Parent)>$($l.Child)>$($l.Cmd)" "Server process $($l.Parent) spawned $($l.Child) (possible web shell)" 'CRITICAL' 'High' @('T1505.003','T1059') `
            "$($l.Parent) started $($l.Child): $($l.Cmd)" @((Ev $l.Src "parent $($l.Parent) -> child $($l.Child) pid $($l.Pid): $($l.Cmd)")) $l.When
    } elseif ($l.Parent -in $Office) {
        Add-Finding 'C1' "$($l.Parent)>$($l.Child)>$($l.Cmd)" "Office application $($l.Parent) spawned $($l.Child) (malicious document)" 'HIGH' 'High' @('T1204.002','T1059') `
            "$($l.Parent) started $($l.Child): $($l.Cmd)" @((Ev $l.Src "parent $($l.Parent) -> child $($l.Child) pid $($l.Pid): $($l.Cmd)")) $l.When
    }
}

# --- C2 process <-> network ------------------------------------------------------------
foreach ($grp in ($Conns | Where-Object { IsPublic $_.RemoteAddress } | Group-Object PID)) {
    $c0 = $grp.Group[0]
    $p = if ($c0.PID -ne $null) { $ProcByPid[[int]$c0.PID] } else { $null }
    $path = if ($p -and $p.ExecutablePath) { $p.ExecutablePath } else { $c0.ProcessPath }
    $leaf = Leaf $(if ($path -and $path -ne 'Access Denied') { $path } else { "$($c0.ProcessName).exe" })
    $why = @()
    $signedOk = $p -and "$($p.SignatureStatus)" -eq 'Valid'
    if ($leaf -in $Shells) { $why += "$leaf is a shell/LOLBin" }
    # Per-user installs of signed apps (Teams, Slack, VS Code, ...) live in AppData and talk to the
    # internet all day: a user-writable path only counts when the binary is not validly signed.
    if ((UserWritable $path) -and -not $signedOk) { $why += "runs from a user-writable path" }
    if ($p -and (Unsigned $p.SignatureStatus)) { $why += "binary is $($p.SignatureStatus)" }
    if (-not $why) { continue }
    $remotes = @($grp.Group | ForEach-Object { "$($_.RemoteAddress):$($_.RemotePort)" } | Sort-Object -Unique)
    $sev = if ($why.Count -ge 2 -or $leaf -in $Shells) { 'HIGH' } else { 'MEDIUM' }
    $ev = @((Ev 'NetworkConnections' "pid $($c0.PID) $leaf -> $($remotes -join ', ')"))
    if ($p) { $ev += Ev 'RunningProcesses' "$($p.ExecutablePath) | signature $($p.SignatureStatus) $($p.Signer) | cmd: $($p.CommandLine)" }
    Add-Finding 'C2' "$($c0.PID)" "$leaf (pid $($c0.PID)) is talking to $($remotes.Count) public address(es)" $sev $(if ($p) { 'High' } else { 'Medium' }) @('T1071','T1105') `
        "$($why -join '; '). Remote: $($remotes -join ', ')" $ev $(if ($p) { $p.StartTime })
}

# --- C3 process <-> persistence ----------------------------------------------------------
foreach ($path in $PersistByPath.Keys) {
    if (-not $ProcPaths.ContainsKey($path)) { continue }
    $p = $ProcPaths[$path]
    $why = @()
    if (UserWritable $path) { $why += 'user-writable path' }
    if (Unsigned $p.SignatureStatus) { $why += "binary $($p.SignatureStatus)" }
    if (-not $why) { continue }
    $ps = $PersistByPath[$path]
    $ev = @((Ev 'RunningProcesses' "pid $($p.PID) $path | signature $($p.SignatureStatus) | cmd: $($p.CommandLine)"))
    $ev += $ps | ForEach-Object { Ev $_.Kind "$($_.Name) -> $($_.Raw)" }
    Add-Finding 'C3' $path "$(Leaf $path) is running AND persisted ($(@($ps.Kind | Sort-Object -Unique) -join ', '))" `
        $(if ($why.Count -ge 2) { 'HIGH' } else { 'MEDIUM' }) 'High' @('T1547','T1053.005','T1543.003') "$($why -join '; ')" $ev $p.StartTime
}

# --- C4 Mark-of-the-Web <-> execution / persistence ---------------------------------------
foreach ($z in ($Zone | Where-Object { "$($_.ZoneID)" -in '3','4' })) {
    $n = Norm $z.FilePath
    $running = $ProcPaths[$n]; $pers = $PersistByPath[$n]
    if (-not $running -and -not $pers) { continue }
    $origin = @($z.HostUrl, $z.ReferrerUrl) | Where-Object { $_ } | Select-Object -First 1
    $ev = @((Ev 'Zone.Identifier' "$($z.FilePath) zone $($z.ZoneID) ($($z.ZoneLabel)) from $origin"))
    if ($running) { $ev += Ev 'RunningProcesses' "pid $($running.PID) signature $($running.SignatureStatus) cmd: $($running.CommandLine)" }
    if ($pers) { $ev += $pers | ForEach-Object { Ev $_.Kind "$($_.Name) -> $($_.Raw)" } }
    Add-Finding 'C4' $n "Downloaded file $(Leaf $n) is $(@($(if ($running) { 'running' }), $(if ($pers) { 'persisted' }) | Where-Object { $_ }) -join ' and ')" `
        $(if ($running -and $pers) { 'HIGH' } else { 'MEDIUM' }) 'High' @('T1204.002','T1105') "Internet-zone file (origin: $origin)" $ev $(if ($running) { $running.StartTime })
}

# --- C5 failed logons -> success from the same source -------------------------------------
$fails = @($SecEvts | Where-Object { $_.EventID -eq 4625 -and $_.EventData.IpAddress -and $_.EventData.IpAddress -notin '-','::1','127.0.0.1' })
$okays = @($SecEvts | Where-Object { $_.EventID -eq 4624 -and $_.EventData.IpAddress -and $_.EventData.LogonType -in '3','10' })
foreach ($g in ($fails | Group-Object { $_.EventData.IpAddress })) {
    if ($g.Count -lt 5) { continue }
    $lastFail = ($g.Group | ForEach-Object { ToUtc $_.TimeCreated } | Sort-Object | Select-Object -Last 1)
    $succ = @($okays | Where-Object { $_.EventData.IpAddress -eq $g.Name } | Where-Object { $t = ToUtc $_.TimeCreated; $t -and $t -ge $lastFail.AddHours(-1) -and $t -le $lastFail.AddHours(24) } |
              Sort-Object { ToUtc $_.TimeCreated })
    if (-not $succ) { continue }
    $users = @($g.Group | ForEach-Object { $_.EventData.TargetUserName } | Sort-Object -Unique)
    $s0 = $succ[0]
    Add-Finding 'C5' $g.Name "$($g.Count) failed logons from $($g.Name) followed by a SUCCESSFUL logon as $($s0.EventData.TargetUserName)" `
        $(if (IsPublic $g.Name) { 'CRITICAL' } else { 'HIGH' }) 'High' @('T1110','T1078') `
        "Targeted accounts: $($users -join ', '). Success: $($s0.Summary)" @(
            (Ev 'Security 4625' "$($g.Count) failures from $($g.Name), last at $($lastFail.ToString('o'))"),
            (Ev 'Security 4624' $s0.Summary)) $s0.TimeCreated
}

# --- C6 account created + added to a privileged group -------------------------------------
$created = @($SecEvts | Where-Object { $_.EventID -eq 4720 })
$adds = @($SecEvts | Where-Object { $_.EventID -in 4728,4732,4756 -and "$($_.EventData.TargetUserName)" -match 'Admin|Operators|Remote Desktop Users|Remote Management Users' })
foreach ($a in $adds) {
    $sid = "$($a.EventData.MemberSid)"
    $c = $created | Where-Object { $sid -and "$($_.EventData.TargetSid)" -eq $sid } | Select-Object -First 1
    if (-not $c) { continue }
    $dt = (ToUtc $a.TimeCreated) - (ToUtc $c.TimeCreated)
    if ([math]::Abs($dt.TotalHours) -gt 24) { continue }
    Add-Finding 'C6' $sid "Account $($c.EventData.TargetUserName) created and added to $($a.EventData.TargetUserName)" 'CRITICAL' 'High' @('T1136.001','T1098') `
        "Created by $($c.EventData.SubjectUserName); added by $($a.EventData.SubjectUserName) $([math]::Round($dt.TotalMinutes)) min later" @(
            (Ev 'Security 4720' $c.Summary), (Ev "Security $($a.EventID)" $a.Summary)) $c.TimeCreated
}

# --- C7 remote logon -> shell/LOLBin by the same user --------------------------------------
$remote = @($SecEvts | Where-Object { $_.EventID -eq 4624 -and $_.EventData.LogonType -in '3','10' -and $_.EventData.IpAddress -and
                                       $_.EventData.IpAddress -notin '-','::1','127.0.0.1' -and "$($_.EventData.TargetUserName)" -notmatch '\$$|^ANONYMOUS' })
if ($remote) {
    foreach ($l in ($lineage | Where-Object { $_.Child -in $Shells -and $_.When })) {
        $p = if ($l.Src -eq 'RunningProcesses') { $ProcByPid[[int]$l.Pid] } else { $null }
        $owner = if ($p -and $p.Owner) { ($p.Owner -split '\\')[-1] } else { $null }
        if (-not $owner) { continue }
        $t = ToUtc $l.When
        $hit = $remote | Where-Object { "$($_.EventData.TargetUserName)" -eq $owner -and ($lt = ToUtc $_.TimeCreated) -and $t -ge $lt -and ($t - $lt).TotalMinutes -le 30 } |
               Select-Object -Last 1
        if (-not $hit) { continue }
        Add-Finding 'C7' "$owner|$($l.Pid)" "Remote logon as $owner from $($hit.EventData.IpAddress), then $($l.Child) run by that user" `
            $(if (IsPublic $hit.EventData.IpAddress) { 'CRITICAL' } else { 'HIGH' }) 'Medium' @('T1021','T1059') `
            "$($hit.Summary) -> $($l.Child): $($l.Cmd)" @((Ev 'Security 4624' $hit.Summary), (Ev $l.Src "pid $($l.Pid) $($l.Child): $($l.Cmd)")) $hit.TimeCreated
    }
}

# --- output -------------------------------------------------------------------------------
$order = @{ CRITICAL = 0; HIGH = 1; MEDIUM = 2 }
$sorted = @($Findings | Sort-Object { $order[$_.Severity] }, FirstSeenUtc)
$JsonFile = Join-Path $BasePath "Correlation_Findings_${HostName}_${Stamp}.json"
[PSCustomObject]@{
    ChainOfCustody = [PSCustomObject]@{ CaseNumber = $CaseNum; Hostname = $HostName; CollectedAt = ([DateTime]::UtcNow).ToString('o'); ToolVersion = $Global:DFIR_ToolVersion }
    ArtifactType   = 'CorrelationFindings'
    RulesEvaluated = @('C1 process lineage','C2 process-network','C3 process-persistence','C4 MOTW-execution','C5 failed-then-successful logon','C6 account created + privileged group','C7 remote logon -> shell')
    Inputs         = [PSCustomObject]$Inputs
    FindingCount   = $sorted.Count
    Findings       = $sorted
} | ConvertTo-Json -Depth 6 | Out-File -FilePath $JsonFile -Encoding UTF8
$h = (Get-FileHash -LiteralPath $JsonFile -Algorithm SHA256).Hash
[PSCustomObject]@{ FileName = $JsonFile; Hash = $h; Generated = ([DateTime]::UtcNow).ToString('o') } | ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8
Write-Log "Correlation complete: $($sorted.Count) finding(s)"
Write-Host ("[+] Correlation: {0} finding(s) ({1})" -f $sorted.Count, (($sorted | Group-Object Severity | ForEach-Object { "$($_.Count) $($_.Name)" }) -join ', ')) -ForegroundColor $(if ($sorted.Count) { 'Yellow' } else { 'Green' })
