<#
.SYNOPSIS
    Module: services â€” installed Windows services with binary identity.
    Migrated from windows-dfir-toolkit Windows_Services.ps1 (analysis logic removed).
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'services: collection started'

$records = foreach ($s in (Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) {
    $exePath  = Resolve-HawkCommandPath $s.PathName
    $identity = if ($exePath) { Get-HawkFileIdentity -Path $exePath }
                else { @{ sha256 = $null; md5 = $null; signatureStatus = 'Unknown'; signer = $null } }

    # svchost-hosted services: hash the service DLL, not just svchost.exe
    $dllPath = $null; $dllIdentity = $null
    if ($s.PathName -match 'svchost(\.exe)?\b' -and $s.Name) {
        try {
            $params = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)\Parameters" -ErrorAction Stop
            if ($params.PSObject.Properties['ServiceDll']) {
                $dllPath = [Environment]::ExpandEnvironmentVariables($params.ServiceDll)
                $dllIdentity = Get-HawkFileIdentity -Path $dllPath
            }
        } catch {}
    }

    [ordered]@{
        name               = $s.Name
        displayName        = $s.DisplayName
        state              = $s.State
        startMode          = $s.StartMode
        account            = $s.StartName
        pathName           = $s.PathName            # raw, never truncated (contract Â§7)
        binaryPath         = $exePath
        sha256             = $identity.sha256
        md5                = $identity.md5
        signatureStatus    = $identity.signatureStatus
        signer             = $identity.signer
        serviceDll         = $dllPath
        serviceDllMd5      = $(if ($dllIdentity) { $dllIdentity.md5 } else { $null })
        serviceDllSha256   = $(if ($dllIdentity) { $dllIdentity.sha256 } else { $null })
        serviceDllSigner   = $(if ($dllIdentity) { $dllIdentity.signer } else { $null })
        serviceDllSigStatus= $(if ($dllIdentity) { $dllIdentity.signatureStatus } else { $null })
        serviceType        = $s.ServiceType
        description        = $s.Description
        processId          = $(if ($s.ProcessId) { [int]$s.ProcessId } else { $null })
    }
}

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'services' -Records $records
