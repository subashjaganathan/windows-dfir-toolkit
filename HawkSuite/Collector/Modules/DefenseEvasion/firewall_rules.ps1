<#
.SYNOPSIS
    Module: firewall_rules - enabled Windows Firewall rules with associated
    program/port. Raw collection only. Migrated from windows-dfir-toolkit
    DefenseEvasion\Firewall_Rules.ps1 (analysis logic removed).
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'firewall_rules: collection started'

$records  = [System.Collections.Generic.List[object]]::new()
$allRules = $null

# Prefer the NetSecurity cmdlets; fall back to netsh parsing if unavailable.
try {
    $allRules = Get-NetFirewallRule -ErrorAction Stop
} catch {
    Write-HawkLog "firewall_rules: Get-NetFirewallRule unavailable ($($_.Exception.Message)); falling back to netsh" 'WARN'
}

if ($null -ne $allRules) {
    # Pre-build filter lookup tables keyed by InstanceID (per-rule *Filter
    # cmdlet calls are extremely slow).
    $portFilters = @{}
    try { Get-NetFirewallPortFilter -ErrorAction Stop | ForEach-Object { $portFilters[$_.InstanceID] = $_ } } catch {}
    $appFilters = @{}
    try { Get-NetFirewallApplicationFilter -ErrorAction Stop | ForEach-Object { $appFilters[$_.InstanceID] = $_ } } catch {}

    $totalCount   = @($allRules).Count
    $enabledRules = @($allRules | Where-Object { "$($_.Enabled)" -eq 'True' -or "$($_.Enabled)" -eq '1' })
    Write-HawkLog "firewall_rules: $totalCount total rules, $($enabledRules.Count) enabled (collecting enabled only)"

    foreach ($rule in $enabledRules) {
        $id   = $rule.InstanceID
        $port = $portFilters[$id]
        $app  = $appFilters[$id]

        $localPort  = if ($port) { @($port.LocalPort)  -join ',' } else { $null }
        $remotePort = if ($port) { @($port.RemotePort) -join ',' } else { $null }

        $records.Add([ordered]@{
            name        = $rule.Name
            displayName = $rule.DisplayName
            direction   = "$($rule.Direction)"
            action      = "$($rule.Action)"
            enabled     = "$($rule.Enabled)"
            profile     = "$($rule.Profile)"
            program     = if ($app)  { $app.Program }   else { $null }
            protocol    = if ($port) { "$($port.Protocol)" } else { $null }
            localPort   = $localPort
            remotePort  = $remotePort
            group       = $rule.Group
        })
    }
}
else {
    # Fallback: parse `netsh advfirewall firewall show rule name=all`.
    $raw = $null
    try { $raw = netsh advfirewall firewall show rule name=all 2>$null } catch {}
    $text   = ($raw -join "`n")
    $blocks = $text -split "`n`n" | Where-Object { $_ -match 'Rule Name:' }
    $total  = 0
    foreach ($block in $blocks) {
        $total++
        $field = {
            param($label)
            $m = [regex]::Match($block, "(?m)^\s*$label\s*:\s*(.+?)\s*$")
            if ($m.Success) { $m.Groups[1].Value } else { $null }
        }
        $enabled = (& $field 'Enabled')
        if ($enabled -notmatch '(?i)yes') { continue }
        $records.Add([ordered]@{
            name        = (& $field 'Rule Name')
            displayName = (& $field 'Rule Name')
            direction   = (& $field 'Direction')
            action      = (& $field 'Action')
            enabled     = $enabled
            profile     = (& $field 'Profiles')
            program     = (& $field 'Program')
            protocol    = (& $field 'Protocol')
            localPort   = (& $field 'LocalPort')
            remotePort  = (& $field 'RemotePort')
            group       = (& $field 'Grouping')
        })
    }
    Write-HawkLog "firewall_rules: netsh fallback parsed $total rule blocks, $($records.Count) enabled"
}

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'firewall_rules' -Records $records
