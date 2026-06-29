<#
.SYNOPSIS
    Module: av_edr_status â€” registered security products, Windows Defender
    runtime status, and Defender exclusions. Raw collection only (no scoring
    of exclusions or tamper state). Migrated from windows-dfir-toolkit
    DefenseEvasion\AV_EDR_Status.ps1 (analysis logic removed).
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'av_edr_status: collection started'

$records = [System.Collections.Generic.List[object]]::new()

# (a) Registered security products via SecurityCenter2 (absent on servers).
try {
    $avList = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop
    foreach ($av in $avList) {
        $records.Add([ordered]@{
            recordType            = 'securityProduct'
            displayName           = $av.displayName
            productState          = [int]$av.productState        # raw int â€” analyzer decodes
            pathToSignedProductExe = $av.pathToSignedProductExe
            timestamp             = ConvertTo-HawkUtc $av.timestamp
        })
    }
} catch {
    Write-HawkLog "av_edr_status: SecurityCenter2 AntiVirusProduct query unavailable ($($_.Exception.Message))" 'WARN'
}

# (b) Windows Defender runtime status.
try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    $records.Add([ordered]@{
        recordType                 = 'defenderStatus'
        amRunning                  = $mp.AMServiceEnabled
        realTimeProtectionEnabled  = $mp.RealTimeProtectionEnabled
        antivirusSignatureLastUpdated = ConvertTo-HawkUtc $mp.AntivirusSignatureLastUpdated
        antivirusSignatureVersion  = $mp.AntivirusSignatureVersion
        tamperProtected            = $mp.IsTamperProtected
        isTamperProtected          = $mp.IsTamperProtected
        behaviorMonitorEnabled     = $mp.BehaviorMonitorEnabled
        ioavProtectionEnabled      = $mp.IoavProtectionEnabled
    })
} catch {
    Write-HawkLog "av_edr_status: Get-MpComputerStatus unavailable ($($_.Exception.Message))" 'WARN'
}

# (b cont.) Defender exclusions â€” one record per path/extension/process.
try {
    $prefs = Get-MpPreference -ErrorAction Stop
    $exclusionMap = [ordered]@{
        path      = $prefs.ExclusionPath
        extension = $prefs.ExclusionExtension
        process   = $prefs.ExclusionProcess
    }
    foreach ($type in $exclusionMap.Keys) {
        foreach ($value in @($exclusionMap[$type])) {
            if (-not $value) { continue }
            $records.Add([ordered]@{
                recordType    = 'defenderExclusion'
                exclusionType = $type
                value         = $value
            })
        }
    }
} catch {
    Write-HawkLog "av_edr_status: Get-MpPreference unavailable ($($_.Exception.Message))" 'WARN'
}

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'av_edr_status' -Records $records
