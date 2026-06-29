<#
.SYNOPSIS
    Module: patch_level â€” installed hotfixes + OS build summary.
    Migrated from windows-dfir-toolkit Patch_Level.ps1 (WU COM history/pending/analysis removed).
    Raw observations only.
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'patch_level: collection started'

$records = New-Object System.Collections.Generic.List[object]

# OS build summary record
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $ubr = $null
    try {
        $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        if ($null -ne $cv.UBR) { $ubr = [int]$cv.UBR }
    } catch { Write-HawkLog "patch_level: UBR read failed - $_" 'WARN' }

    $records.Add([ordered]@{
        recordType    = 'osBuild'
        caption       = $os.Caption
        version       = $os.Version
        buildNumber   = $os.BuildNumber
        ubr           = $ubr
        osArchitecture = $os.OSArchitecture
        installDate   = ConvertTo-HawkUtc $os.InstallDate
    })
} catch {
    Write-HawkLog "patch_level: Win32_OperatingSystem query failed - $_" 'WARN'
}

# Installed hotfixes
try {
    foreach ($hf in (Get-CimInstance Win32_QuickFixEngineering -ErrorAction Stop)) {
        $records.Add([ordered]@{
            recordType     = 'hotfix'
            hotfixId       = $hf.HotFixID
            description    = $hf.Description
            installedOnUtc = ConvertTo-HawkUtc $hf.InstalledOn
            installedBy    = $hf.InstalledBy
        })
    }
} catch {
    Write-HawkLog "patch_level: Win32_QuickFixEngineering query failed - $_" 'WARN'
}

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'patch_level' -Records $records
