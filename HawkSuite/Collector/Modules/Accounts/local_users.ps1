<#
.SYNOPSIS
    Module: local_users â€” local accounts + group memberships.
    Migrated from windows-dfir-toolkit Local_Users_Groups.ps1 (analysis logic removed).
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'local_users: collection started'

# group â†’ members map in one pass (Win32_GroupUser is expensive; do it once)
$membership = @{}
foreach ($gu in (Get-CimInstance Win32_GroupUser -ErrorAction SilentlyContinue)) {
    if ($gu.GroupComponent.Domain -ne $env:COMPUTERNAME) { continue }
    $group = $gu.GroupComponent.Name
    $member = "$($gu.PartComponent.Domain)\$($gu.PartComponent.Name)"
    if (-not $membership.ContainsKey($member)) { $membership[$member] = New-Object System.Collections.Generic.List[string] }
    $membership[$member].Add($group)
}

$records = foreach ($u in (Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction SilentlyContinue)) {
    $key = "$($u.Domain)\$($u.Name)"
    [ordered]@{
        name             = $u.Name
        domain           = $u.Domain
        sid              = $u.SID
        disabled         = [bool]$u.Disabled
        lockout          = [bool]$u.Lockout
        passwordRequired = [bool]$u.PasswordRequired
        passwordChangeable = [bool]$u.PasswordChangeable
        description      = $u.Description
        groups           = @($(if ($membership.ContainsKey($key)) { $membership[$key] } else { @() }))
    }
}

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'local_users' -Records $records
