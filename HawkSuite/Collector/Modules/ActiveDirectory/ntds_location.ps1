<#
.SYNOPSIS
    Module: ntds_location - NTDS.dit / SYSVOL locations and AD database config
    (domain controllers). RAW collection only. Empty on non-DC hosts.
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'ntds_location: collection started'

$records = New-Object System.Collections.Generic.List[object]

function Get-NtdsVal([string]$path, [string]$name) {
    try { $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($path); if ($k) { return $k.GetValue($name) } } catch {}
    $null
}

try {
    $ntds = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Services\NTDS\Parameters')
    if ($ntds) {
        $records.Add([ordered]@{
            recordType         = 'ntdsConfig'
            ditPath            = "$(Get-NtdsVal 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'DSA Database file')"
            logPath            = "$(Get-NtdsVal 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'Database log files path')"
            workingDirectory   = "$(Get-NtdsVal 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'DSA Working Directory')"
        })
    } else { Write-HawkLog 'ntds_location: NTDS service not present (not a domain controller)' }

    $sysvol = Get-NtdsVal 'SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'SysVol'
    if ($sysvol) { $records.Add([ordered]@{ recordType = 'sysvol'; path = "$sysvol" }) }
} catch { Write-HawkLog "ntds_location: read failed - $_" 'WARN' }

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'ntds_location' -Records $records
