<#
.SYNOPSIS
    Module: wmi_persistence â€” WMI event subscription persistence (T1546.003).
    Migrated from windows-dfir-toolkit WMI_Persistence.ps1 (analysis logic removed).
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'wmi_persistence: collection started'
$records = New-Object System.Collections.Generic.List[object]
$ns = 'root\subscription'

foreach ($f in (Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction SilentlyContinue)) {
    $records.Add([ordered]@{
        objectType   = 'EventFilter'
        name         = $f.Name
        query        = $f.Query            # raw, never truncated
        queryLanguage= $f.QueryLanguage
        eventNamespace = $f.EventNamespace
        consumerType = $null; destination = $null; filterRef = $null; consumerRef = $null
    })
}

foreach ($c in (Get-CimInstance -Namespace $ns -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue)) {
    $records.Add([ordered]@{
        objectType   = 'CommandLineEventConsumer'
        name         = $c.Name
        query        = $null; queryLanguage = $null; eventNamespace = $null
        consumerType = 'CommandLine'
        destination  = ("$($c.ExecutablePath) $($c.CommandLineTemplate)").Trim()
        filterRef = $null; consumerRef = $null
    })
}

foreach ($c in (Get-CimInstance -Namespace $ns -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue)) {
    $dest = $(if ($c.ScriptFileName) { $c.ScriptFileName } else { $c.ScriptText })
    $records.Add([ordered]@{
        objectType   = 'ActiveScriptEventConsumer'
        name         = $c.Name
        query        = $null; queryLanguage = $null; eventNamespace = $null
        consumerType = "ActiveScript($($c.ScriptingEngine))"
        destination  = $dest                # full script text preserved (contract Â§7)
        filterRef = $null; consumerRef = $null
    })
}

foreach ($b in (Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue)) {
    $records.Add([ordered]@{
        objectType   = 'FilterToConsumerBinding'
        name         = $null
        query        = $null; queryLanguage = $null; eventNamespace = $null
        consumerType = $null; destination = $null
        filterRef    = "$($b.Filter)"
        consumerRef  = "$($b.Consumer)"
    })
}

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'wmi_persistence' -Records $records
