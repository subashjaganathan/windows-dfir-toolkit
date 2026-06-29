<#
.SYNOPSIS
    Module: arp_entries â€” ARP/neighbor cache (lateral-movement context).
    Migrated from windows-dfir-toolkit ARP_Entries.ps1.
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'arp_entries: collection started'
$records = New-Object System.Collections.Generic.List[object]

if (Get-Command Get-NetNeighbor -ErrorAction SilentlyContinue) {
    foreach ($n in (Get-NetNeighbor -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Unreachable' })) {
        $records.Add([ordered]@{
            interfaceAlias = $n.InterfaceAlias
            ipAddress      = "$($n.IPAddress)"
            macAddress     = "$($n.LinkLayerAddress)"
            state          = "$($n.State)"
            addressFamily  = "$($n.AddressFamily)"
        })
    }
} else {
    foreach ($line in (arp -a)) {
        if ($line -match '^\s+(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-f-]{17})\s+(\w+)') {
            $records.Add([ordered]@{
                interfaceAlias = $null
                ipAddress      = $Matches[1]
                macAddress     = $Matches[2]
                state          = $Matches[3]
                addressFamily  = 'IPv4'
            })
        }
    }
}

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'arp_entries' -Records $records
