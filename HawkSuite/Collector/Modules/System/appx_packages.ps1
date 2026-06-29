<#
.SYNOPSIS
    Module: appx_packages — installed AppX/UWP package inventory (raw).
    Migrated from windows-dfir-toolkit AppX_UWP_Apps.ps1 (analysis logic removed).
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'appx_packages: collection started'

$records = New-Object System.Collections.Generic.List[object]

# Get-AppxPackage -AllUsers requires elevation; fall back to current-user scope.
$packages = @()
try {
    $packages = @(Get-AppxPackage -AllUsers -ErrorAction Stop)
} catch {
    Write-HawkLog "appx_packages: -AllUsers query failed, retrying current-user scope - $_" 'WARN'
    try {
        $packages = @(Get-AppxPackage -ErrorAction Stop)
    } catch {
        Write-HawkLog "appx_packages: Get-AppxPackage failed - $_" 'WARN'
        $packages = @()
    }
}

foreach ($pkg in $packages) {
    try {
        $version       = $null
        $architecture  = $null
        $signatureKind = $null
        try { if ($pkg.Version)       { $version       = $pkg.Version.ToString() } }       catch {}
        try { if ($pkg.Architecture)  { $architecture  = $pkg.Architecture.ToString() } }  catch {}
        try { if ($pkg.SignatureKind) { $signatureKind = $pkg.SignatureKind.ToString() } } catch {}

        $records.Add([ordered]@{
            recordType      = 'appxPackage'
            name            = $pkg.Name
            packageFullName = $pkg.PackageFullName
            publisher       = $pkg.Publisher
            publisherId     = $pkg.PublisherId
            version         = $version
            architecture    = $architecture
            installLocation = $pkg.InstallLocation
            signatureKind   = $signatureKind
            isFramework     = [bool]$pkg.IsFramework
            isBundle        = [bool]$pkg.IsBundle
        })
    } catch {
        Write-HawkLog "appx_packages: failed to process a package - $_" 'WARN'
    }
}

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'appx_packages' -Records $records
