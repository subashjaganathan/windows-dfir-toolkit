<#
.SYNOPSIS
    Module: network_connections â€” TCP connections + UDP endpoints with process correlation.
    Migrated from windows-dfir-toolkit Network_Connections.ps1 (analysis logic removed).
    Falls back to netstat parsing on hosts without the NetTCPIP module (Win7).
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'network_connections: collection started'

# PID â†’ name/path lookup, one pass
$procs = @{}
foreach ($p in (Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) {
    $procs[[int]$p.ProcessId] = @{ name = $p.Name; path = $p.ExecutablePath }
}

$records = New-Object System.Collections.Generic.List[object]

$haveNetTcp = Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue
if ($haveNetTcp) {
    foreach ($c in (Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
        $ownerPid = [int]$c.OwningProcess
        $proc = $procs[$ownerPid]
        $records.Add([ordered]@{
            protocol        = 'TCP'
            localAddress    = "$($c.LocalAddress)"
            localPort       = [int]$c.LocalPort
            remoteAddress   = "$($c.RemoteAddress)"
            remotePort      = [int]$c.RemotePort
            state           = "$($c.State)"
            pid             = $ownerPid
            processName     = $(if ($proc) { $proc.name } else { $null })
            processPath     = $(if ($proc) { $proc.path } else { $null })
            creationTimeUtc = ConvertTo-HawkUtc $c.CreationTime
        })
    }
    foreach ($u in (Get-NetUDPEndpoint -ErrorAction SilentlyContinue)) {
        $ownerPid = [int]$u.OwningProcess
        $proc = $procs[$ownerPid]
        $records.Add([ordered]@{
            protocol        = 'UDP'
            localAddress    = "$($u.LocalAddress)"
            localPort       = [int]$u.LocalPort
            remoteAddress   = $null
            remotePort      = $null
            state           = 'Stateless'
            pid             = $ownerPid
            processName     = $(if ($proc) { $proc.name } else { $null })
            processPath     = $(if ($proc) { $proc.path } else { $null })
            creationTimeUtc = ConvertTo-HawkUtc $u.CreationTime
        })
    }
} else {
    # Win7 / stripped installs: parse netstat -ano
    Write-HawkLog 'network_connections: NetTCPIP unavailable, using netstat fallback' 'WARN'
    foreach ($line in (netstat -ano | Select-Object -Skip 4)) {
        $f = ($line.Trim() -split '\s+')
        if ($f.Count -lt 4) { continue }
        $proto = $f[0].ToUpper()
        if ($proto -ne 'TCP' -and $proto -ne 'UDP') { continue }
        $isTcp = $proto -eq 'TCP'
        $ownerPid = [int]$f[$f.Count - 1]
        $proc = $procs[$ownerPid]
        $localParts  = $f[1] -split ':(?=[^:\]]*$)'   # split on last colon (IPv6-safe)
        $remoteParts = $f[2] -split ':(?=[^:\]]*$)'
        $records.Add([ordered]@{
            protocol        = $proto
            localAddress    = $localParts[0]
            localPort       = [int]$localParts[1]
            remoteAddress   = $(if ($isTcp) { $remoteParts[0] } else { $null })
            remotePort      = $(if ($isTcp -and $remoteParts[1] -ne '0') { [int]$remoteParts[1] } else { $null })
            state           = $(if ($isTcp) { $f[3] } else { 'Stateless' })
            pid             = $ownerPid
            processName     = $(if ($proc) { $proc.name } else { $null })
            processPath     = $(if ($proc) { $proc.path } else { $null })
            creationTimeUtc = $null   # netstat does not expose it; stays null (contract Â§6)
        })
    }
}

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'network_connections' -Records $records
