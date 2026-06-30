<#
.SYNOPSIS
    Module: remote_access_tools - presence and usage evidence for RMM / remote-
    access software (AnyDesk, TeamViewer, ScreenConnect/ConnectWise, Atera,
    Splashtop, LogMeIn, VNC, ngrok, Chrome Remote Desktop, etc.). Captures
    install/process/service presence plus connection-log metadata and a bounded
    tail - those logs frequently hold the remote operator's IP / client ID.
    RMM abuse is a top initial-access & persistence vector. RAW collection only.
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'remote_access_tools: collection started'

$records   = New-Object System.Collections.Generic.List[object]
$TailLines = 400

# Broad keyword set matched against process / service / uninstall display names.
$ratPattern = '(?i)anydesk|teamviewer|screenconnect|connectwise|\batera\b|splashtop|logmein|gotoassist|gotomypc|remoteutilities|\bsupremo\b|ultravnc|tightvnc|realvnc|tigervnc|\bvnc\b|ninjarmm|ninja ?one|kaseya|datto|zoho assist|dwservice|dwagent|action1|pulseway|\bsyncro\b|ateraagent|\bngrok\b|chrome remote desktop|remote desktop manager|mremoteng|\brustdesk\b|\bmeshagent\b|meshcentral|quickassist|distant'

function Get-Tail([string]$path, [int]$n) {
    try {
        $all = [System.IO.File]::ReadAllLines($path)
        if ($all.Count -le $n) { return ,$all }
        return ,($all[($all.Count - $n)..($all.Count - 1)])
    } catch { return ,@() }
}

# (a) Running processes that look like remote-access tools.
try {
    foreach ($p in (Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match $ratPattern -or $_.ExecutablePath -match $ratPattern })) {
        $id = if ($p.ExecutablePath) { Get-HawkFileIdentity -Path $p.ExecutablePath } else { @{ sha256=$null; md5=$null; signatureStatus='Unknown'; signer=$null } }
        $records.Add([ordered]@{
            recordType  = 'ratProcess'
            name        = $p.Name
            pid         = [int]$p.ProcessId
            path        = $p.ExecutablePath
            commandLine = $p.CommandLine
            sha256      = $id.sha256
            signatureStatus = $id.signatureStatus
            signer      = $id.signer
        })
    }
} catch { Write-HawkLog "remote_access_tools: process scan failed - $_" 'WARN' }

# (b) Services whose name/display/binary matches.
try {
    foreach ($s in (Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match $ratPattern -or $_.DisplayName -match $ratPattern -or $_.PathName -match $ratPattern })) {
        $records.Add([ordered]@{
            recordType  = 'ratService'
            serviceName = $s.Name
            displayName = $s.DisplayName
            state       = "$($s.State)"
            startMode   = "$($s.StartMode)"
            startName   = $s.StartName
            pathName    = $s.PathName
        })
    }
} catch { Write-HawkLog "remote_access_tools: service scan failed - $_" 'WARN' }

# (c) Installed-software (Uninstall keys, HKLM native + WOW64 + per-user HKU).
$uninstallRoots = @(
    @{ hive = [Microsoft.Win32.Registry]::LocalMachine; key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' },
    @{ hive = [Microsoft.Win32.Registry]::LocalMachine; key = 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' }
)
foreach ($r in $uninstallRoots) {
    try {
        $base = $r.hive.OpenSubKey($r.key)
        if (-not $base) { continue }
        foreach ($sub in $base.GetSubKeyNames()) {
            $k = $base.OpenSubKey($sub)
            if (-not $k) { continue }
            $dn = "$($k.GetValue('DisplayName'))"
            if (-not $dn -or $dn -notmatch $ratPattern) { continue }
            $records.Add([ordered]@{
                recordType      = 'ratInstalled'
                displayName     = $dn
                version         = "$($k.GetValue('DisplayVersion'))"
                publisher       = "$($k.GetValue('Publisher'))"
                installLocation = "$($k.GetValue('InstallLocation'))"
                installDate     = "$($k.GetValue('InstallDate'))"
            })
        }
    } catch { Write-HawkLog "remote_access_tools: uninstall walk failed ($($r.key)) - $_" 'WARN' }
}

# (d) Connection / session logs for the high-value tools (contain remote IPs/IDs).
#     Metadata + capped recent tail; full logs remain on disk.
$logGlobs = @(
    @{ tool = 'AnyDesk';      paths = @("$env:ProgramData\AnyDesk\connection_trace.txt", "$env:ProgramData\AnyDesk\ad.trace", "$env:ProgramData\AnyDesk\ad_svc.trace") },
    @{ tool = 'TeamViewer';   paths = @("$env:ProgramData\TeamViewer\Connections_incoming.txt", "${env:ProgramFiles}\TeamViewer\Connections_incoming.txt", "${env:ProgramFiles(x86)}\TeamViewer\Connections_incoming.txt") },
    @{ tool = 'ScreenConnect';paths = @("$env:ProgramData\ScreenConnect Client*\*.log") },
    @{ tool = 'Splashtop';    paths = @("$env:ProgramData\Splashtop\Temp\log\*.log") },
    @{ tool = 'RustDesk';     paths = @("$env:ProgramData\RustDesk\*.log", "$env:APPDATA\RustDesk\*.log") }
)
foreach ($g in $logGlobs) {
    foreach ($pat in $g.paths) {
        try {
            foreach ($f in (Get-ChildItem -Path $pat -File -ErrorAction SilentlyContinue)) {
                $records.Add([ordered]@{
                    recordType      = 'ratConnectionLog'
                    tool            = $g.tool
                    path            = $f.FullName
                    sizeBytes       = $f.Length
                    lastModifiedUtc = ConvertTo-HawkUtc $f.LastWriteTimeUtc
                    recentLines     = Get-Tail $f.FullName $TailLines
                })
            }
        } catch { Write-HawkLog "remote_access_tools: log read failed ($($g.tool)) - $_" 'WARN' }
    }
}

# (e) AnyDesk user-id / config + Chrome Remote Desktop host registry (presence).
try {
    foreach ($u in (Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {
        $adConf = Join-Path $u.FullName 'AppData\Roaming\AnyDesk\user.conf'
        try {
            if (Test-Path -LiteralPath $adConf -ErrorAction Stop) {
                $records.Add([ordered]@{ recordType='ratConfig'; tool='AnyDesk'; user=$u.Name; path=$adConf
                    lastModifiedUtc = ConvertTo-HawkUtc (Get-Item -LiteralPath $adConf).LastWriteTimeUtc })
            }
        } catch {}
    }
} catch {}

if ($records.Count -eq 0) { Write-HawkLog 'remote_access_tools: no remote-access tools detected' }

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'remote_access_tools' -Records $records
