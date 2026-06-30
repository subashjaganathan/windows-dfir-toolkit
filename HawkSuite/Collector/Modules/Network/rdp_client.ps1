<#
.SYNOPSIS
    Module: rdp_client - outbound RDP (mstsc) usage evidence: servers this host
    connected TO, typed-target MRU, redirected local devices, RDP bitmap-cache
    file metadata, and saved .rdp connection files. Proves lateral movement
    originating from this host. RAW collection only (registry reads are HKCU =
    collector's user; cache/.rdp file scan covers all user profiles).
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'rdp_client: collection started'

$records = New-Object System.Collections.Generic.List[object]

# (a) Servers connected to (HKCU TSC\Servers) - one record per remote host.
try {
    $servers = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Terminal Server Client\Servers')
    if ($servers) {
        foreach ($srv in $servers.GetSubKeyNames()) {
            $sk = $servers.OpenSubKey($srv)
            $records.Add([ordered]@{
                recordType   = 'rdpServer'
                server       = $srv
                usernameHint = if ($sk) { "$($sk.GetValue('UsernameHint'))" } else { $null }
            })
        }
    }
} catch { Write-HawkLog "rdp_client: TSC\Servers walk failed - $_" 'WARN' }

# (b) Typed-target MRU (HKCU TSC\Default: MRU0..MRUn).
try {
    $def = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Terminal Server Client\Default')
    if ($def) {
        foreach ($vn in $def.GetValueNames()) {
            if ($vn -notmatch '^MRU') { continue }
            $records.Add([ordered]@{
                recordType = 'rdpTargetMru'
                valueName  = $vn
                target     = "$($def.GetValue($vn))"
            })
        }
    }
} catch { Write-HawkLog "rdp_client: TSC\Default MRU walk failed - $_" 'WARN' }

# (c) Redirected local devices (HKCU TSC\LocalDevices) - drive/printer mapping.
try {
    $ld = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Terminal Server Client\LocalDevices')
    if ($ld) {
        foreach ($vn in $ld.GetValueNames()) {
            $records.Add([ordered]@{
                recordType = 'rdpLocalDevice'
                target     = $vn
                flags      = $ld.GetValue($vn)
            })
        }
    }
} catch { Write-HawkLog "rdp_client: TSC\LocalDevices walk failed - $_" 'WARN' }

# (d) RDP bitmap cache files + saved .rdp files across all user profiles (metadata only).
try {
    foreach ($u in (Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {
        $cacheDir = Join-Path $u.FullName 'AppData\Local\Microsoft\Terminal Server Client\Cache'
        $hasCache = $false
        try { $hasCache = Test-Path -LiteralPath $cacheDir -ErrorAction Stop } catch {}
        if ($hasCache) {
            try {
                foreach ($f in (Get-ChildItem -LiteralPath $cacheDir -File -ErrorAction SilentlyContinue)) {
                    $records.Add([ordered]@{
                        recordType      = 'rdpBitmapCache'
                        user            = $u.Name
                        name            = $f.Name
                        path            = $f.FullName
                        sizeBytes       = $f.Length
                        lastModifiedUtc = ConvertTo-HawkUtc $f.LastWriteTimeUtc
                    })
                }
            } catch {}
        }
        # Saved .rdp connection files in the profile's Documents folder.
        $docs = Join-Path $u.FullName 'Documents'
        try {
            if (Test-Path -LiteralPath $docs -ErrorAction Stop) {
                foreach ($rdp in (Get-ChildItem -LiteralPath $docs -Filter '*.rdp' -File -Force -ErrorAction SilentlyContinue)) {
                    $records.Add([ordered]@{
                        recordType      = 'rdpFile'
                        user            = $u.Name
                        name            = $rdp.Name
                        path            = $rdp.FullName
                        sizeBytes       = $rdp.Length
                        lastModifiedUtc = ConvertTo-HawkUtc $rdp.LastWriteTimeUtc
                        sha256          = (Get-HawkFileIdentity -Path $rdp.FullName).sha256
                    })
                }
            }
        } catch {}
    }
} catch { Write-HawkLog "rdp_client: cache/.rdp file scan failed - $_" 'WARN' }

if ($records.Count -eq 0) { Write-HawkLog 'rdp_client: no outbound RDP usage evidence present' }

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'rdp_client' -Records $records
