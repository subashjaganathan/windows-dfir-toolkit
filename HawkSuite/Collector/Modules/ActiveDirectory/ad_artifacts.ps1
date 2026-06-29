<#
.SYNOPSIS
    Module: ad_artifacts - domain context + privileged group membership via
    ADSI (no RSAT dependency). RAW collection only. Graceful-empty on workgroup
    hosts (the [ADSISearcher]/domain binding simply fails and is logged).
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'ad_artifacts: collection started'

$records = New-Object System.Collections.Generic.List[object]

# Bail cleanly if this host is not domain-joined.
$partOfDomain = $false
try { $partOfDomain = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain } catch {}
if (-not $partOfDomain) {
    Write-HawkLog 'ad_artifacts: host not domain-joined; skipping'
    Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'ad_artifacts' -Records $records
    return
}

# (a) Domain info
try {
    $root = [ADSI]'LDAP://RootDSE'
    $domainDN = "$($root.defaultNamingContext)"
    $records.Add([ordered]@{
        recordType        = 'domainInfo'
        defaultNamingCtx  = $domainDN
        dnsHostName       = "$($root.dnsHostName)"
        forestFunctionality = "$($root.forestFunctionality)"
        domainController  = "$($root.serverName)"
    })

    # (b) Privileged group membership (well-known groups by name)
    foreach ($grp in 'Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Backup Operators') {
        try {
            $searcher = New-Object DirectoryServices.DirectorySearcher
            $searcher.Filter = "(&(objectCategory=group)(cn=$grp))"
            $res = $searcher.FindOne()
            if (-not $res) { continue }
            $members = $res.Properties['member']
            foreach ($m in $members) {
                $records.Add([ordered]@{ recordType = 'privilegedGroupMember'; group = $grp; memberDn = "$m" })
            }
        } catch { Write-HawkLog "ad_artifacts: group '$grp' query failed - $_" 'WARN' }
    }
} catch { Write-HawkLog "ad_artifacts: domain binding failed - $_" 'WARN' }

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'ad_artifacts' -Records $records
