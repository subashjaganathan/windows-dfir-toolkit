<#
.SYNOPSIS
    Module: kerberoast_spn - inventory of domain accounts with SPNs (the
    Kerberoasting attack surface) via ADSI. RAW collection only - records the
    SPN inventory; the analyzer assesses risk. Graceful-empty off-domain.
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'kerberoast_spn: collection started'

$records = New-Object System.Collections.Generic.List[object]

$partOfDomain = $false
try { $partOfDomain = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain } catch {}
if (-not $partOfDomain) {
    Write-HawkLog 'kerberoast_spn: host not domain-joined; skipping'
    Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'kerberoast_spn' -Records $records
    return
}

try {
    # USER accounts (not computers) that have an SPN are the kerberoastable set.
    $searcher = New-Object DirectoryServices.DirectorySearcher
    $searcher.Filter = '(&(objectCategory=user)(servicePrincipalName=*))'
    $searcher.PageSize = 500
    [void]$searcher.PropertiesToLoad.AddRange(@('samAccountName','servicePrincipalName','pwdLastSet','memberOf','userAccountControl'))
    foreach ($res in $searcher.FindAll()) {
        $p = $res.Properties
        $pwdLast = $null
        try { if ($p['pwdlastset'].Count) { $pwdLast = ConvertTo-HawkUtc ([DateTime]::FromFileTimeUtc([int64]$p['pwdlastset'][0])) } } catch {}
        foreach ($spn in $p['serviceprincipalname']) {
            $records.Add([ordered]@{
                recordType      = 'spnAccount'
                samAccountName  = "$($p['samaccountname'][0])"
                spn             = "$spn"
                pwdLastSetUtc   = $pwdLast
                memberOf        = (($p['memberof'] | ForEach-Object { "$_" }) -join '; ')
            })
        }
    }
} catch { Write-HawkLog "kerberoast_spn: SPN search failed - $_" 'WARN' }

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'kerberoast_spn' -Records $records
