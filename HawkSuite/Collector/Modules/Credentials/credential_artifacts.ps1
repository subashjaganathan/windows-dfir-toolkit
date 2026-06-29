<#
.SYNOPSIS
    Module: credential_artifacts â€” credential-related METADATA only.
    Migrated from windows-dfir-toolkit Credential_Artifacts.ps1 (analysis/notes removed).
    NEVER reads secret material: only settings, vault entry names, and key file COUNTS.
    Raw observations only.
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'credential_artifacts: collection started'

$records = New-Object System.Collections.Generic.List[object]

# (a) WDigest UseLogonCredential
try {
    $wd = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -ErrorAction SilentlyContinue
    $useLogonCred = if ($wd -and $null -ne $wd.UseLogonCredential) { [int]$wd.UseLogonCredential } else { $null }
    $records.Add([ordered]@{
        recordType        = 'wdigestSetting'
        useLogonCredential = $useLogonCred
    })
} catch {
    Write-HawkLog "credential_artifacts: WDigest read failed - $_" 'WARN'
    $records.Add([ordered]@{ recordType = 'wdigestSetting'; useLogonCredential = $null })
}

# (b) LSA Protection RunAsPPL
try {
    $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
    $runAsPpl = if ($lsa -and $null -ne $lsa.RunAsPPL) { [int]$lsa.RunAsPPL } else { $null }
    $records.Add([ordered]@{
        recordType = 'lsaProtection'
        runAsPpl   = $runAsPpl
    })
} catch {
    Write-HawkLog "credential_artifacts: LSA read failed - $_" 'WARN'
    $records.Add([ordered]@{ recordType = 'lsaProtection'; runAsPpl = $null })
}

# (c) Credential Manager vault entry target NAMES only (no passwords)
try {
    $cmdkeyOut = (& cmdkey /list 2>$null) -join "`n"
    $entries = $cmdkeyOut -split "(?=Target:)" | Where-Object { $_ -match 'Target:' }
    foreach ($entry in $entries) {
        $target = if ($entry -match 'Target:\s*(.+)') { $Matches[1].Trim() } else { $null }
        $type   = if ($entry -match 'Type:\s*(.+)')   { $Matches[1].Trim() } else { $null }
        $user   = if ($entry -match 'User:\s*(.+)')   { $Matches[1].Trim() } else { $null }
        $records.Add([ordered]@{
            recordType = 'credManVault'
            target     = $target
            type       = $type
            user       = $user
        })
    }
} catch {
    Write-HawkLog "credential_artifacts: cmdkey /list failed - $_" 'WARN'
}

# (d) DPAPI master key COUNT per user (count + path only, no contents)
try {
    $usersRoot = Join-Path $env:SystemDrive 'Users'
    if (Test-Path $usersRoot) {
        foreach ($userDir in (Get-ChildItem -LiteralPath $usersRoot -Directory -ErrorAction SilentlyContinue)) {
            $protectPath = Join-Path $userDir.FullName 'AppData\Roaming\Microsoft\Protect'
            # Test-Path throws UnauthorizedAccessException on other users' dirs
            # when unelevated; treat any access failure as "not present".
            $exists = $false
            try { $exists = Test-Path -LiteralPath $protectPath -ErrorAction Stop } catch { continue }
            if (-not $exists) { continue }
            try {
                $count = @(Get-ChildItem -LiteralPath $protectPath -Recurse -File -Force -ErrorAction SilentlyContinue).Count
                $records.Add([ordered]@{
                    recordType = 'dpapiMasterKeyCount'
                    userName   = $userDir.Name
                    path       = $protectPath
                    fileCount  = $count
                })
            } catch {
                Write-HawkLog "credential_artifacts: DPAPI count failed for $protectPath - $_" 'WARN'
            }
        }
    }
} catch {
    Write-HawkLog "credential_artifacts: DPAPI enumeration failed - $_" 'WARN'
}

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'credential_artifacts' -Records $records
