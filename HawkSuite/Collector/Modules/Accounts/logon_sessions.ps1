<#
.SYNOPSIS
    Module: logon_sessions â€” active logon sessions with user mapping.
    Migrated from windows-dfir-toolkit Logon_Sessions_Deep.ps1 (analysis logic removed).
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'logon_sessions: collection started'

$logonTypes = @{
    0='System'; 2='Interactive'; 3='Network'; 4='Batch'; 5='Service'
    7='Unlock'; 8='NetworkCleartext'; 9='NewCredentials'; 10='RemoteInteractive'; 11='CachedInteractive'
}

# logonId â†’ user via association class
$sessionUser = @{}
foreach ($lu in (Get-CimInstance Win32_LoggedOnUser -ErrorAction SilentlyContinue)) {
    $logonId = $lu.Dependent.LogonId
    $sessionUser[$logonId] = "$($lu.Antecedent.Domain)\$($lu.Antecedent.Name)"
}

$records = foreach ($s in (Get-CimInstance Win32_LogonSession -ErrorAction SilentlyContinue)) {
    $typeCode = [int]$s.LogonType
    [ordered]@{
        logonId               = $s.LogonId
        user                  = $sessionUser[$s.LogonId]
        logonTypeCode         = $typeCode
        logonType             = $(if ($logonTypes.ContainsKey($typeCode)) { $logonTypes[$typeCode] } else { "Unknown($typeCode)" })
        authenticationPackage = $s.AuthenticationPackage
        startTimeUtc          = ConvertTo-HawkUtc $s.StartTime
    }
}

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'logon_sessions' -Records $records
