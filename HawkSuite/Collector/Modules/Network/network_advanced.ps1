<#
.SYNOPSIS
    Module: network_advanced — listeners, UDP endpoints, routes, adapters.
    RAW collection only. recordType discriminates: listener | udpEndpoint | route | adapter.
    Migrated from windows-dfir-toolkit Network_Advanced.ps1 (analysis logic removed).
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'network_advanced: collection started'

$records = New-Object System.Collections.Generic.List[object]

# Pre-build a pid -> process lookup once (avoids per-connection Get-Process cost).
$procById = @{}
try {
    foreach ($p in (Get-Process -ErrorAction Stop)) {
        if (-not $procById.ContainsKey([int]$p.Id)) { $procById[[int]$p.Id] = $p }
    }
} catch { Write-HawkLog "network_advanced: process lookup build failed - $_" 'WARN' }

function Get-NAProcInfo {
    param([int]$OwningPid)
    $name = $null; $path = $null
    if ($procById.ContainsKey($OwningPid)) {
        $proc = $procById[$OwningPid]
        $name = $proc.ProcessName
        try { $path = $proc.Path } catch { $path = $null }
    }
    $identity = if ($path) { Get-HawkFileIdentity -Path $path }
                else { @{ sha256 = $null; md5 = $null; signatureStatus = 'Unknown'; signer = $null } }
    [pscustomobject]@{
        processName     = $name
        processPath     = $path
        sha256          = $identity.sha256
        md5             = $identity.md5
        signatureStatus = $identity.signatureStatus
        signer          = $identity.signer
    }
}

# (a) TCP listeners ------------------------------------------------------------
$tcpOk = $false
try {
    $listeners = Get-NetTCPConnection -State Listen -ErrorAction Stop
    $tcpOk = $true
    foreach ($l in $listeners) {
        $owningPid = [int]$l.OwningProcess
        $pi = Get-NAProcInfo -OwningPid $owningPid
        $records.Add([ordered]@{
            recordType      = 'listener'
            localAddress    = $l.LocalAddress
            localPort       = [int]$l.LocalPort
            owningPid       = $owningPid
            processName     = $pi.processName
            processPath     = $pi.processPath
            sha256          = $pi.sha256
            md5             = $pi.md5
            signatureStatus = $pi.signatureStatus
            signer          = $pi.signer
        })
    }
} catch {
    Write-HawkLog "network_advanced: Get-NetTCPConnection listeners failed - $_" 'WARN'
}

# netstat fallback for listeners only if Get-NetTCPConnection failed
if (-not $tcpOk) {
    try {
        $netstatLines = & netstat -ano -p TCP
        foreach ($line in $netstatLines) {
            $t = $line.Trim()
            if ($t -notmatch 'LISTENING') { continue }
            $cols = $t -split '\s+'
            if ($cols.Count -lt 5) { continue }
            $local = $cols[1]
            $owningPid = 0; [void][int]::TryParse($cols[4], [ref]$owningPid)
            $lport = $null
            $idx = $local.LastIndexOf(':')
            $laddr = $local
            if ($idx -ge 0) {
                $laddr = $local.Substring(0, $idx)
                $portStr = $local.Substring($idx + 1)
                $pv = 0; if ([int]::TryParse($portStr, [ref]$pv)) { $lport = $pv }
            }
            $pi = Get-NAProcInfo -OwningPid $owningPid
            $records.Add([ordered]@{
                recordType      = 'listener'
                localAddress    = $laddr
                localPort       = $lport
                owningPid       = $owningPid
                processName     = $pi.processName
                processPath     = $pi.processPath
                sha256          = $pi.sha256
                md5             = $pi.md5
                signatureStatus = $pi.signatureStatus
                signer          = $pi.signer
            })
        }
    } catch {
        Write-HawkLog "network_advanced: netstat fallback failed - $_" 'WARN'
    }
}

# (b) UDP endpoints ------------------------------------------------------------
try {
    foreach ($u in (Get-NetUDPEndpoint -ErrorAction Stop)) {
        $owningPid = [int]$u.OwningProcess
        $pi = Get-NAProcInfo -OwningPid $owningPid
        $records.Add([ordered]@{
            recordType   = 'udpEndpoint'
            localAddress = $u.LocalAddress
            localPort    = [int]$u.LocalPort
            owningPid    = $owningPid
            processName  = $pi.processName
            processPath  = $pi.processPath
        })
    }
} catch {
    Write-HawkLog "network_advanced: Get-NetUDPEndpoint failed - $_" 'WARN'
}

# (c) Routes -------------------------------------------------------------------
try {
    foreach ($r in (Get-NetRoute -ErrorAction Stop)) {
        $records.Add([ordered]@{
            recordType        = 'route'
            destinationPrefix = $r.DestinationPrefix
            nextHop           = $r.NextHop
            interfaceAlias    = $r.InterfaceAlias
            routeMetric       = [int]$r.RouteMetric
        })
    }
} catch {
    Write-HawkLog "network_advanced: Get-NetRoute failed - $_" 'WARN'
}

# (d) Adapters -----------------------------------------------------------------
try {
    foreach ($a in (Get-NetAdapter -ErrorAction Stop)) {
        $ipv4 = $null; $dns = $null
        # Direct cmdlets instead of Get-NetIPConfiguration: the composite cmdlet
        # emits noisy non-terminating errors for transient/stale interfaces.
        try {
            $addrs = Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
            if ($addrs) { $ipv4 = (($addrs.IPAddress | Where-Object { $_ }) -join ', ') }
        } catch {}
        try {
            $ds = Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
            if ($ds) { $dns = (($ds.ServerAddresses | Where-Object { $_ }) -join ', ') }
        } catch {}
        $records.Add([ordered]@{
            recordType  = 'adapter'
            name        = $a.Name
            macAddress  = $a.MacAddress
            status      = "$($a.Status)"
            ipv4        = $ipv4
            dnsServers  = $dns
        })
    }
} catch {
    Write-HawkLog "network_advanced: Get-NetAdapter failed - $_" 'WARN'
}

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'network_advanced' -Records $records
