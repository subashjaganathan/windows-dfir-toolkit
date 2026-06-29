<#
.SYNOPSIS
    Module: dns_cache â€” client DNS resolver cache.
    Migrated from windows-dfir-toolkit DNS_Cache.ps1. Fallback: ipconfig /displaydns.
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'dns_cache: collection started'
$records = New-Object System.Collections.Generic.List[object]

if (Get-Command Get-DnsClientCache -ErrorAction SilentlyContinue) {
    foreach ($e in (Get-DnsClientCache -ErrorAction SilentlyContinue)) {
        $records.Add([ordered]@{
            name       = $e.Name
            entry      = $e.Entry
            recordType = "$($e.Type)"
            status     = "$($e.Status)"
            ttlSeconds = [int]$e.TimeToLive
            data       = $e.Data
        })
    }
} else {
    Write-HawkLog 'dns_cache: Get-DnsClientCache unavailable, parsing ipconfig /displaydns' 'WARN'
    $current = $null
    foreach ($line in (ipconfig /displaydns)) {
        if ($line -match '^\s{4}(\S.*?)\s*$' -and $line -notmatch ':') { $current = $Matches[1]; continue }
        if ($null -ne $current -and $line -match '(A|AAAA|CNAME|PTR)\s*\(Host\)?\s*Record.*:\s*(\S+)') {
            $records.Add([ordered]@{
                name = $current; entry = $current; recordType = $Matches[1]
                status = $null; ttlSeconds = $null; data = $Matches[2]
            })
        }
    }
}

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'dns_cache' -Records $records
