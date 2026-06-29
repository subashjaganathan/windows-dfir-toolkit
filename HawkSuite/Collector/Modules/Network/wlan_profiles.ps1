<#
.SYNOPSIS
    Module: wlan_profiles - saved wireless network profiles (movement/location
    history) + the hosts file (DNS hijack evidence). RAW collection only.
    Does NOT use 'key=clear' - WiFi passwords are never collected.
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'wlan_profiles: collection started'

$records = New-Object System.Collections.Generic.List[object]

# (a) WLAN profiles via netsh (no key material)
try {
    $list = netsh wlan show profiles 2>$null
    $names = @()
    foreach ($line in $list) {
        # single capturing regex (a two-condition -and re-sets $Matches to the
        # last pattern, which has no group 1 -> .Trim() on null throws)
        if ($line -match '(?:All User Profile|User Profile)\s*:\s*(.+?)\s*$') {
            $names += ($Matches[1].Trim())
        }
    }
    foreach ($name in ($names | Select-Object -Unique)) {
        $ssid = $null; $auth = $null; $cipher = $null; $mode = $null
        try {
            $detail = netsh wlan show profile name="$name" 2>$null
            foreach ($d in $detail) {
                if ($d -match 'SSID name\s*:\s*"?(.+?)"?\s*$')      { $ssid = $Matches[1].Trim() }
                elseif ($d -match 'Authentication\s*:\s*(.+?)\s*$') { $auth = $Matches[1].Trim() }
                elseif ($d -match 'Cipher\s*:\s*(.+?)\s*$')         { $cipher = $Matches[1].Trim() }
                elseif ($d -match 'Connection mode\s*:\s*(.+?)\s*$'){ $mode = $Matches[1].Trim() }
            }
        } catch {}
        $records.Add([ordered]@{
            recordType     = 'wlanProfile'
            profileName    = $name
            ssidName       = $ssid
            authentication = $auth
            cipher         = $cipher
            connectionMode = $mode
        })
    }
} catch { Write-HawkLog "wlan_profiles: netsh wlan unavailable (no wireless adapter?) - $_" 'WARN' }

# (b) hosts file (read as clean string[] via ReadAllLines)
try {
    $hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    if (Test-Path -LiteralPath $hosts -ErrorAction SilentlyContinue) {
        $lines = [System.IO.File]::ReadAllLines($hosts)
        $entries = New-Object System.Collections.Generic.List[object]
        foreach ($ln in $lines) {
            $t = $ln.Trim()
            if ($t.Length -eq 0 -or $t.StartsWith('#')) { continue }
            $parts = $t -split '\s+', 2
            if ($parts.Count -eq 2) { $entries.Add([ordered]@{ ip = $parts[0]; host = $parts[1] }) }
        }
        $item = Get-Item -LiteralPath $hosts -ErrorAction SilentlyContinue
        $records.Add([ordered]@{
            recordType      = 'hostsFile'
            path            = $hosts
            lastModifiedUtc = if ($item) { ConvertTo-HawkUtc $item.LastWriteTimeUtc } else { $null }
            entryCount      = $entries.Count
            entries         = $entries
            lines           = $lines
        })
    }
} catch { Write-HawkLog "wlan_profiles: hosts file read failed - $_" 'WARN' }

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'wlan_profiles' -Records $records
