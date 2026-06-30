<#
.SYNOPSIS
    Module: smb_shares_sessions - SMB exposure and live access: shares this host
    serves (incl. non-default/hidden), inbound SMB sessions and open files (who
    is connected IN), and outbound mapped drives / SMB mappings (where this host
    is connected OUT). Core lateral-movement evidence. RAW collection only.
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'smb_shares_sessions: collection started'

$records = New-Object System.Collections.Generic.List[object]

# (a) Local shares served by this host. Prefer Get-SmbShare; fall back to CIM.
$gotShares = $false
try {
    foreach ($s in (Get-SmbShare -ErrorAction Stop)) {
        $records.Add([ordered]@{
            recordType  = 'smbShare'
            name        = $s.Name
            path        = $s.Path
            description = $s.Description
            shareType   = "$($s.ShareType)"
            scopeName   = $s.ScopeName
            special     = [bool]$s.Special           # admin/IPC default shares
            currentUsers = $s.CurrentUsers
        })
    }
    $gotShares = $true
} catch { Write-HawkLog "smb_shares_sessions: Get-SmbShare unavailable, trying Win32_Share - $_" 'WARN' }

if (-not $gotShares) {
    try {
        foreach ($s in (Get-CimInstance Win32_Share -ErrorAction SilentlyContinue)) {
            $records.Add([ordered]@{
                recordType  = 'smbShare'
                name        = $s.Name
                path        = $s.Path
                description = $s.Description
                shareType   = "$($s.Type)"
                special     = ($s.Name -match '\$$')
            })
        }
    } catch { Write-HawkLog "smb_shares_sessions: Win32_Share query failed - $_" 'WARN' }
}

# (b) Share-level access permissions (who is granted what on each share).
# Pipe from Get-SmbShare per-share; Get-SmbShareAccess does not accept a wildcard -Name.
try {
    foreach ($a in (Get-SmbShare -ErrorAction Stop | Get-SmbShareAccess -ErrorAction Stop)) {
        $records.Add([ordered]@{
            recordType    = 'smbShareAccess'
            shareName     = $a.Name
            accountName   = $a.AccountName
            accessControl = "$($a.AccessControlType)"
            accessRight   = "$($a.AccessRight)"
        })
    }
} catch { Write-HawkLog "smb_shares_sessions: Get-SmbShareAccess unavailable - $_" 'WARN' }

# (c) Inbound SMB sessions - remote hosts/users connected TO this machine.
try {
    foreach ($sess in (Get-SmbSession -ErrorAction Stop)) {
        $records.Add([ordered]@{
            recordType    = 'smbSession'
            clientName    = $sess.ClientComputerName
            clientUser    = $sess.ClientUserName
            numOpenFiles  = $sess.NumOpens
            sessionId     = "$($sess.SessionId)"
        })
    }
} catch { Write-HawkLog "smb_shares_sessions: Get-SmbSession unavailable (needs elevation/server) - $_" 'WARN' }

# (d) Open files served over SMB - what inbound sessions are touching.
try {
    foreach ($of in (Get-SmbOpenFile -ErrorAction Stop)) {
        $records.Add([ordered]@{
            recordType = 'smbOpenFile'
            clientName = $of.ClientComputerName
            clientUser = $of.ClientUserName
            path       = $of.Path
            shareName  = $of.ShareRelativePath
        })
    }
} catch { Write-HawkLog "smb_shares_sessions: Get-SmbOpenFile unavailable (needs elevation/server) - $_" 'WARN' }

# (e) Outbound mapped drives / SMB mappings - where this host connects OUT.
try {
    foreach ($m in (Get-SmbMapping -ErrorAction Stop)) {
        $records.Add([ordered]@{
            recordType   = 'smbMapping'
            localPath    = $m.LocalPath
            remotePath   = $m.RemotePath
            status       = "$($m.Status)"
        })
    }
} catch { Write-HawkLog "smb_shares_sessions: Get-SmbMapping unavailable - $_" 'WARN' }

# (f) Persistent mapped drives from HKCU\Network (collector's user).
try {
    $net = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Network')
    if ($net) {
        foreach ($drive in $net.GetSubKeyNames()) {
            $dk = $net.OpenSubKey($drive)
            if (-not $dk) { continue }
            $records.Add([ordered]@{
                recordType  = 'mappedDriveRegistry'
                driveLetter = $drive
                remotePath  = "$($dk.GetValue('RemotePath'))"
                userName    = "$($dk.GetValue('UserName'))"
                provider    = "$($dk.GetValue('ProviderName'))"
            })
        }
    }
} catch { Write-HawkLog "smb_shares_sessions: HKCU\Network walk failed - $_" 'WARN' }

if ($records.Count -eq 0) { Write-HawkLog 'smb_shares_sessions: no SMB shares/sessions/mappings present' }

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'smb_shares_sessions' -Records $records
