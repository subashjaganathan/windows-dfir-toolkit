<#
.SYNOPSIS
    Module: cloud_artifacts - OneDrive accounts/config + third-party sync clients.
    RAW collection only (config/metadata; no file contents). recordType per source.
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'cloud_artifacts: collection started'

$records = New-Object System.Collections.Generic.List[object]

# (a) OneDrive accounts (current user)
try {
    $acc = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\OneDrive\Accounts')
    if ($acc) {
        foreach ($name in $acc.GetSubKeyNames()) {
            $k = $acc.OpenSubKey($name)
            if (-not $k) { continue }
            $records.Add([ordered]@{
                recordType  = 'oneDriveAccount'
                accountKey  = $name
                userEmail   = "$($k.GetValue('UserEmail'))"
                userFolder  = "$($k.GetValue('UserFolder'))"
                displayName = "$($k.GetValue('DisplayName'))"
                cid         = "$($k.GetValue('cid'))"
            })
        }
    }
} catch { Write-HawkLog "cloud_artifacts: OneDrive accounts failed - $_" 'WARN' }

# (b) OneDrive config/version
try {
    $od = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\OneDrive')
    if ($od) {
        $records.Add([ordered]@{
            recordType = 'oneDriveConfig'
            installed  = $true
            version    = "$($od.GetValue('Version'))"
            userFolder = "$($od.GetValue('UserFolder'))"
        })
    }
} catch { Write-HawkLog "cloud_artifacts: OneDrive config failed - $_" 'WARN' }

# (c) Third-party sync clients (presence + path only)
function Add-Provider($name, $paths) {
    foreach ($p in $paths) {
        try {
            if (Test-Path -LiteralPath $p -ErrorAction SilentlyContinue) {
                $item = Get-Item -LiteralPath $p -ErrorAction SilentlyContinue
                $records.Add([ordered]@{
                    recordType      = 'thirdPartySync'
                    provider        = $name
                    installed       = $true
                    path            = $p
                    lastModifiedUtc = if ($item) { ConvertTo-HawkUtc $item.LastWriteTimeUtc } else { $null }
                })
                return
            }
        } catch {}
    }
    $records.Add([ordered]@{ recordType = 'thirdPartySync'; provider = $name; installed = $false; path = $null; lastModifiedUtc = $null })
}
try {
    Add-Provider 'GoogleDrive' @('C:\Program Files\Google\Drive File Stream', "$env:LOCALAPPDATA\Google\DriveFS")
    Add-Provider 'Dropbox'     @("$env:APPDATA\Dropbox\info.json", "$env:LOCALAPPDATA\Dropbox")
    Add-Provider 'Box'         @('C:\Program Files\Box\Box', "$env:LOCALAPPDATA\Box\Box")
} catch { Write-HawkLog "cloud_artifacts: third-party scan failed - $_" 'WARN' }

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'cloud_artifacts' -Records $records
