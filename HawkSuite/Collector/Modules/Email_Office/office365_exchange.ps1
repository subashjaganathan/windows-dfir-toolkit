<#
.SYNOPSIS
    Module: office365_exchange - Outlook profile accounts, inbox-rule metadata,
    auto-forward settings (BEC indicators) and Microsoft/O365 identity cache.
    Migrated from windows-dfir-toolkit Email_Office\Office365_Exchange.ps1.
    RAW collection only (metadata; NO message bodies, NO rule contents, NO
    tokens). Registry reads are HKCU (collector's user) + HKLM (all identities).
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'office365_exchange: collection started'

$records  = New-Object System.Collections.Generic.List[object]
$versions = @('16.0', '15.0', '14.0')

# (a) Outlook profile accounts - server/account names per profile (HKCU).
foreach ($ver in $versions) {
    try {
        $profKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Software\Microsoft\Office\$ver\Outlook\Profiles")
        if (-not $profKey) { continue }
        foreach ($profName in $profKey.GetSubKeyNames()) {
            $prof = $profKey.OpenSubKey($profName)
            if (-not $prof) { continue }
            $stack = New-Object System.Collections.Generic.Stack[object]
            $stack.Push($prof)
            while ($stack.Count -gt 0) {
                $node = $stack.Pop()
                $acct   = "$($node.GetValue('Account Name'))"
                $server = "$($node.GetValue('POP3 Server'))"
                if (-not $server) { $server = "$($node.GetValue('IMAP Server'))" }
                if (-not $server) { $server = "$($node.GetValue('EAS Server Name'))" }
                $smtp   = "$($node.GetValue('SMTP Email Address'))"
                if ($acct -or $server -or $smtp) {
                    $records.Add([ordered]@{
                        recordType  = 'outlookAccount'
                        officeVer   = $ver
                        profile     = $profName
                        accountName = $acct
                        server      = $server
                        smtpAddress = $smtp
                    })
                }
                # rule metadata sometimes lives under profile subkeys
                $ruleName = $node.GetValue('Rule Name'); if (-not $ruleName) { $ruleName = $node.GetValue('RuleName') }
                if ($ruleName) {
                    $records.Add([ordered]@{
                        recordType = 'outlookInboxRule'
                        officeVer  = $ver
                        profile    = $profName
                        ruleName   = "$ruleName"
                    })
                }
                foreach ($sub in $node.GetSubKeyNames()) {
                    $child = $node.OpenSubKey($sub)
                    if ($child) { $stack.Push($child) }
                }
            }
        }
    } catch { Write-HawkLog "office365_exchange: profile walk failed ($ver) - $_" 'WARN' }
}

# (b) Auto-forward configuration (mailbox exfil / BEC indicator) - raw values.
foreach ($ver in @('16.0', '15.0')) {
    try {
        $mk = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Software\Microsoft\Office\$ver\Outlook\Options\Mail")
        if (-not $mk) { continue }
        $records.Add([ordered]@{
            recordType      = 'outlookMailOptions'
            officeVer       = $ver
            autoForward     = $mk.GetValue('AutoForward')
            oofForwardState = $mk.GetValue('OOFForwardState')
        })
    } catch { Write-HawkLog "office365_exchange: mail options read failed ($ver) - $_" 'WARN' }
}

# (c) Legacy Windows Messaging Subsystem profiles (HKCU).
try {
    $wms = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey(
        'Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles')
    if ($wms) {
        foreach ($p in $wms.GetSubKeyNames()) {
            $records.Add([ordered]@{ recordType = 'messagingProfile'; profile = $p })
        }
    }
} catch { Write-HawkLog "office365_exchange: messaging subsystem walk failed - $_" 'WARN' }

# (d) Microsoft/O365 identity cache (HKLM IdentityStore LogonCache) - names only.
try {
    $cacheBase = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\IdentityStore\LogonCache')
    if ($cacheBase) {
        foreach ($provider in $cacheBase.GetSubKeyNames()) {
            $pk = $cacheBase.OpenSubKey($provider)
            if (-not $pk) { continue }
            foreach ($grp in $pk.GetSubKeyNames()) {
                $gk = $pk.OpenSubKey($grp)
                if (-not $gk) { continue }
                foreach ($entry in $gk.GetSubKeyNames()) {
                    $ek = $gk.OpenSubKey($entry)
                    if (-not $ek) { continue }
                    $identity = "$($ek.GetValue('IdentityName'))"
                    if (-not $identity) { continue }
                    $records.Add([ordered]@{
                        recordType   = 'identityCacheEntry'
                        providerId   = $provider
                        identityName = $identity
                        displayName  = "$($ek.GetValue('DisplayName'))"
                        givenName    = "$($ek.GetValue('GivenName'))"
                    })
                }
            }
        }
    }
} catch { Write-HawkLog "office365_exchange: identity cache walk failed - $_" 'WARN' }

if ($records.Count -eq 0) { Write-HawkLog 'office365_exchange: no Outlook/O365 artifacts present for current user' }

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'office365_exchange' -Records $records
