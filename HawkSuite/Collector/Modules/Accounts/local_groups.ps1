<#
.SYNOPSIS
    Module: local_groups â€” local groups and their members (one record per group,member).
    Migrated from windows-dfir-toolkit Local_Users_Groups.ps1 (group portion; analysis removed).
    Raw observations only.
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'local_groups: collection started'

$records = New-Object System.Collections.Generic.List[object]

$usedFallback = $false
$groups = $null
try { $groups = @(Get-LocalGroup -ErrorAction Stop) } catch {
    Write-HawkLog "local_groups: Get-LocalGroup failed, falling back to net localgroup - $_" 'WARN'
    $usedFallback = $true
}

if (-not $usedFallback -and $groups) {
    foreach ($g in $groups) {
        $groupSid = if ($g.SID) { $g.SID.Value } else { $null }
        $members = @()
        try {
            $members = @(Get-LocalGroupMember -Group $g.Name -ErrorAction Stop)
        } catch {
            Write-HawkLog "local_groups: Get-LocalGroupMember failed for '$($g.Name)' - $_" 'WARN'
        }
        if ($members.Count -eq 0) {
            # Emit the group even with no members so the group itself is recorded
            $records.Add([ordered]@{
                groupName            = $g.Name
                groupSid             = $groupSid
                memberName           = $null
                memberSid            = $null
                memberObjectClass    = $null
                memberPrincipalSource = $null
            })
            continue
        }
        foreach ($m in $members) {
            $records.Add([ordered]@{
                groupName            = $g.Name
                groupSid             = $groupSid
                memberName           = $m.Name
                memberSid            = if ($m.SID) { $m.SID.Value } else { $null }
                memberObjectClass    = "$($m.ObjectClass)"
                memberPrincipalSource = "$($m.PrincipalSource)"
            })
        }
    }
} else {
    # Fallback: parse 'net localgroup' output (no SIDs available).
    try {
        $groupNames = @()
        $listOut = & net localgroup 2>$null
        foreach ($line in $listOut) {
            if ($line -match '^\*(.+)$') { $groupNames += $Matches[1].Trim() }
        }
        foreach ($gn in $groupNames) {
            $memberNames = @()
            try {
                $detail = & net localgroup "$gn" 2>$null
                $capture = $false
                foreach ($line in $detail) {
                    if ($line -match '^-{4,}') { $capture = $true; continue }
                    if (-not $capture) { continue }
                    if ($line -match '^The command completed') { break }
                    $t = $line.Trim()
                    if ($t) { $memberNames += $t }
                }
            } catch {
                Write-HawkLog "local_groups: net localgroup '$gn' failed - $_" 'WARN'
            }
            if ($memberNames.Count -eq 0) {
                $records.Add([ordered]@{
                    groupName            = $gn
                    groupSid             = $null
                    memberName           = $null
                    memberSid            = $null
                    memberObjectClass    = $null
                    memberPrincipalSource = $null
                })
                continue
            }
            foreach ($mn in $memberNames) {
                $records.Add([ordered]@{
                    groupName            = $gn
                    groupSid             = $null
                    memberName           = $mn
                    memberSid            = $null
                    memberObjectClass    = $null
                    memberPrincipalSource = $null
                })
            }
        }
    } catch {
        Write-HawkLog "local_groups: net localgroup fallback failed - $_" 'WARN'
    }
}

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'local_groups' -Records $records
