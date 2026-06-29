<#
.SYNOPSIS
    Module: system_info — host identity, OS, uptime, hotfixes (single-record artifact).
    Migrated from windows-dfir-toolkit System_Info.ps1 + Patch_Level.ps1.
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'system_info: collection started'

$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue

$hotfixes = @(Get-CimInstance Win32_QuickFixEngineering -ErrorAction SilentlyContinue |
    ForEach-Object { [ordered]@{ hotFixId = $_.HotFixID; description = $_.Description
                                 installedOnUtc = ConvertTo-HawkUtc $_.InstalledOn } })

$record = [ordered]@{
    hostname        = $env:COMPUTERNAME
    domain          = $cs.Domain
    domainJoined    = [bool]$cs.PartOfDomain
    osCaption       = $os.Caption
    osVersion       = $os.Version
    osBuild         = [int]$os.BuildNumber
    osArchitecture  = $os.OSArchitecture
    osInstallDateUtc= ConvertTo-HawkUtc $os.InstallDate
    lastBootUtc     = ConvertTo-HawkUtc $os.LastBootUpTime
    timeZone        = (Get-TimeZone).Id
    manufacturer    = $cs.Manufacturer
    model           = $cs.Model
    biosSerial      = $(if ($bios) { $bios.SerialNumber } else { $null })
    totalMemoryMB   = [int]($cs.TotalPhysicalMemory / 1MB)
    hotfixes        = $hotfixes
}

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'system_info' -Records @($record)
