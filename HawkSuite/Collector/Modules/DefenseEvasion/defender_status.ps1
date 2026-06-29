<#
.SYNOPSIS
    Module: defender_status — AV/EDR state as raw observations (single-record artifact).
    Migrated from windows-dfir-toolkit AV_EDR_Status.ps1 (analysis logic removed):
    exclusion paths are RECORDED, not judged — the analyzer decides what's anomalous.
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'defender_status: collection started'

$defender = $null
try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    $defender = [ordered]@{
        amServiceEnabled        = [bool]$mp.AMServiceEnabled
        realTimeProtection      = [bool]$mp.RealTimeProtectionEnabled
        behaviorMonitor         = [bool]$mp.BehaviorMonitorEnabled
        ioavProtection          = [bool]$mp.IoavProtectionEnabled
        onAccessProtection      = [bool]$mp.OnAccessProtectionEnabled
        tamperProtection        = $(if ($mp.PSObject.Properties['IsTamperProtected']) { [bool]$mp.IsTamperProtected } else { $null })
        antivirusSignatureAgeDays = [int]$mp.AntivirusSignatureAge
        antivirusSignatureLastUpdatedUtc = ConvertTo-HawkUtc $mp.AntivirusSignatureLastUpdated
        fullScanAgeDays         = $(if ("$($mp.FullScanAge)" -ne '4294967295') { [int]$mp.FullScanAge } else { $null })
        quickScanAgeDays        = $(if ("$($mp.QuickScanAge)" -ne '4294967295') { [int]$mp.QuickScanAge } else { $null })
    }
} catch { Write-HawkLog "defender_status: Get-MpComputerStatus unavailable: $_" 'WARN' }

$exclusions = $null
try {
    $pref = Get-MpPreference -ErrorAction Stop
    $exclusions = [ordered]@{
        paths      = @($pref.ExclusionPath)
        extensions = @($pref.ExclusionExtension)
        processes  = @($pref.ExclusionProcess)
        disableRealtimeMonitoring = [bool]$pref.DisableRealtimeMonitoring
    }
} catch { Write-HawkLog "defender_status: Get-MpPreference unavailable: $_" 'WARN' }

$avProducts = @()
try {
    # SecurityCenter2 exists on workstations only — absence on servers is normal
    foreach ($av in (Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop)) {
        $state = [int]$av.productState
        $avProducts += [ordered]@{
            displayName     = $av.displayName
            pathToSignedExe = $av.pathToSignedProductExe
            productStateRaw = $state
            realTimeOn      = (($state -band 0x1000) -ne 0)   # documented SECURITY_PRODUCT bit
            definitionsUpToDate = (($state -band 0x10) -eq 0)
        }
    }
} catch {}

# Security/EDR services present (observation only — list is of service patterns, not verdicts)
$securityServices = @()
$knownPatterns = @{
    'CrowdStrike Falcon' = 'CSFalconService'; 'SentinelOne' = 'SentinelAgent'
    'Carbon Black' = 'CbDefense*'; 'Cortex XDR' = 'cyserver'; 'Cybereason' = 'CybereasonActiveProbe'
    'Microsoft Defender for Endpoint' = 'Sense'; 'Sophos' = 'Sophos*'; 'Trellix/McAfee' = 'masvc'
    'Symantec SEP' = 'SepMasterService'; 'TrendMicro' = 'ntrtscan'; 'Elastic Agent' = 'Elastic Agent'
    'Qualys' = 'QualysAgent'; 'Tanium' = 'Tanium*'; 'Velociraptor' = 'Velociraptor'
}
foreach ($vendor in $knownPatterns.Keys) {
    foreach ($svc in (Get-Service -Name $knownPatterns[$vendor] -ErrorAction SilentlyContinue)) {
        $securityServices += [ordered]@{
            vendor = $vendor; serviceName = $svc.Name; status = "$($svc.Status)"
        }
    }
}

$record = [ordered]@{
    defender         = $defender
    exclusions       = $exclusions
    avProducts       = $avProducts
    securityServices = $securityServices
}

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'defender_status' -Records @($record)
