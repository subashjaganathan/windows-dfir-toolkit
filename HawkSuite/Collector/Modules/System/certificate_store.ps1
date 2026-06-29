<#
.SYNOPSIS
    Module: certificate_store â€” certificates in LocalMachine Root/CA/My/
    TrustedPublisher stores. Raw collection only (no rogue-root/expiry
    verdicts). Migrated from windows-dfir-toolkit Certificates\Certificate_Store.ps1
    (analysis logic removed).
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'certificate_store: collection started'

$records = [System.Collections.Generic.List[object]]::new()
$stores  = 'Root','CA','My','TrustedPublisher'

foreach ($storeName in $stores) {
    try {
        $certs = Get-ChildItem "Cert:\LocalMachine\$storeName" -ErrorAction Stop
        foreach ($cert in $certs) {
            $sigAlg = $null
            try { $sigAlg = $cert.SignatureAlgorithm.FriendlyName } catch {}

            $records.Add([ordered]@{
                store              = $storeName
                subject            = $cert.Subject
                issuer             = $cert.Issuer
                thumbprint         = $cert.Thumbprint
                serialNumber       = $cert.SerialNumber
                notBeforeUtc       = ConvertTo-HawkUtc $cert.NotBefore
                notAfterUtc        = ConvertTo-HawkUtc $cert.NotAfter
                hasPrivateKey      = $cert.HasPrivateKey
                friendlyName       = $cert.FriendlyName
                signatureAlgorithm = $sigAlg
            })
        }
    } catch {
        Write-HawkLog "certificate_store: store '$storeName' inaccessible ($($_.Exception.Message))" 'WARN'
    }
}

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'certificate_store' -Records $records
