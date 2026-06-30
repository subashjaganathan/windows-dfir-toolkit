<#
.SYNOPSIS
    Module: vss_shadows - Volume Shadow Copy inventory and System Restore points.
    Records each shadow copy (Win32_ShadowCopy), restore-point history, and the
    backup/restore service states. Migrated from windows-dfir-toolkit
    FileSystem\Backup_VSS_Deep.ps1. RAW collection only - shadow-deletion /
    ransomware scoring is left to the analyzer (it reads System-log event IDs).
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'vss_shadows: collection started'

$records = New-Object System.Collections.Generic.List[object]

# (a) Volume Shadow Copies.
try {
    foreach ($s in (Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue)) {
        $records.Add([ordered]@{
            recordType       = 'shadowCopy'
            id               = $s.ID
            volumeName       = $s.VolumeName
            deviceObject     = $s.DeviceObject
            originatingMachine = $s.OriginatingMachine
            creationUtc      = ConvertTo-HawkUtc $s.InstallDate
            clientAccessible = $s.ClientAccessible
            persistent       = $s.Persistent
            state            = $s.State
            count            = $s.Count
        })
    }
} catch { Write-HawkLog "vss_shadows: Win32_ShadowCopy query failed - $_" 'WARN' }

# (b) Shadow storage allocation per volume (capacity context).
try {
    foreach ($a in (Get-CimInstance Win32_ShadowStorage -ErrorAction SilentlyContinue)) {
        $records.Add([ordered]@{
            recordType    = 'shadowStorage'
            allocatedSpace = $a.AllocatedSpace
            usedSpace      = $a.UsedSpace
            maxSpace       = $a.MaxSpace
        })
    }
} catch { Write-HawkLog "vss_shadows: Win32_ShadowStorage query failed - $_" 'WARN' }

# (c) System Restore points.
try {
    $rps = @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue)
    foreach ($rp in $rps) {
        $created = $null
        try { $created = [System.Management.ManagementDateTimeConverter]::ToDateTime($rp.CreationTime) } catch {}
        $records.Add([ordered]@{
            recordType         = 'restorePoint'
            sequenceNumber     = $rp.SequenceNumber
            description        = $rp.Description
            restorePointType   = $rp.RestorePointType
            eventType          = $rp.EventType
            creationUtc        = ConvertTo-HawkUtc $created
        })
    }
} catch { Write-HawkLog "vss_shadows: restore point enumeration failed (System Restore may be disabled) - $_" 'WARN' }

# (d) Backup / restore-related service states (raw status, no verdict).
foreach ($svcName in @('VSS', 'swprv', 'wbengine', 'fhsvc', 'SDRSVC')) {
    try {
        $svc = Get-Service $svcName -ErrorAction SilentlyContinue
        if ($svc) {
            $records.Add([ordered]@{
                recordType  = 'backupService'
                serviceName = $svcName
                displayName = $svc.DisplayName
                status      = "$($svc.Status)"
                startType   = "$($svc.StartType)"
            })
        }
    } catch { Write-HawkLog "vss_shadows: service query failed ($svcName) - $_" 'WARN' }
}

if ($records.Count -eq 0) { Write-HawkLog 'vss_shadows: no shadow copies or restore points present' }

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'vss_shadows' -Records $records
