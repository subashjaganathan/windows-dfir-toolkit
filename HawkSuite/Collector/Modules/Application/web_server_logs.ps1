<#
.SYNOPSIS
    Module: web_server_logs - IIS request logs + Windows Firewall log inventory.
    Records each log file's metadata plus a capped recent tail (these logs can
    be GBs; the full files remain on disk). RAW collection only.
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'web_server_logs: collection started'

$records = New-Object System.Collections.Generic.List[object]
$TailLines = 500   # recent lines per log (triage tail; full file is too large to embed)

function Get-Tail([string]$path, [int]$n) {
    try {
        $all = [System.IO.File]::ReadAllLines($path)
        if ($all.Count -le $n) { return ,$all }
        return ,($all[($all.Count - $n)..($all.Count - 1)])
    } catch { return ,@() }
}

# (a) IIS request logs
try {
    $iisRoots = @('C:\inetpub\logs\LogFiles', (Join-Path $env:SystemDrive 'inetpub\logs\LogFiles'))
    foreach ($root in ($iisRoots | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $root -ErrorAction SilentlyContinue)) { continue }
        foreach ($f in (Get-ChildItem -LiteralPath $root -Recurse -File -Filter '*.log' -ErrorAction SilentlyContinue | Select-Object -First 2000)) {
            $records.Add([ordered]@{
                recordType      = 'iisLog'
                site            = (Split-Path (Split-Path $f.FullName -Parent) -Leaf)
                path            = $f.FullName
                sizeBytes       = $f.Length
                lastModifiedUtc = ConvertTo-HawkUtc $f.LastWriteTimeUtc
                recentLines     = Get-Tail $f.FullName $TailLines
            })
        }
    }
} catch { Write-HawkLog "web_server_logs: IIS log scan failed - $_" 'WARN' }

# (b) Windows Firewall log (off by default; present when logging enabled)
try {
    $fwCandidates = @(
        (Join-Path $env:SystemRoot 'System32\LogFiles\Firewall\pfirewall.log'),
        (Join-Path $env:SystemRoot 'System32\LogFiles\Firewall\domainfw.log'),
        (Join-Path $env:SystemRoot 'System32\LogFiles\Firewall\privatefw.log'),
        (Join-Path $env:SystemRoot 'System32\LogFiles\Firewall\publicfw.log')
    )
    foreach ($fw in ($fwCandidates | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $fw -ErrorAction SilentlyContinue)) { continue }
        $item = Get-Item -LiteralPath $fw -ErrorAction SilentlyContinue
        $records.Add([ordered]@{
            recordType      = 'firewallLog'
            path            = $fw
            sizeBytes       = if ($item) { $item.Length } else { $null }
            lastModifiedUtc = if ($item) { ConvertTo-HawkUtc $item.LastWriteTimeUtc } else { $null }
            recentLines     = Get-Tail $fw $TailLines
        })
    }
} catch { Write-HawkLog "web_server_logs: firewall log read failed - $_" 'WARN' }

if ($records.Count -eq 0) { Write-HawkLog 'web_server_logs: no IIS/firewall logs present' }

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'web_server_logs' -Records $records
