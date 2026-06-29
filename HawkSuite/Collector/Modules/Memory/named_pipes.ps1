<#
.SYNOPSIS
    Module: named_pipes â€” open named pipes (C2 framework default-profile detection
    happens analyzer-side against Configuration/IOC/known-bad-handles.json).
    Migrated from windows-dfir-toolkit Named_Pipes.ps1 (analysis logic removed).
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'named_pipes: collection started'

$records = New-Object System.Collections.Generic.List[object]
try {
    foreach ($pipe in ([System.IO.Directory]::GetFiles('\\.\pipe\'))) {
        $records.Add([ordered]@{
            name = $pipe.Substring(9)    # strip \\.\pipe\
            fullPath = $pipe
        })
    }
} catch {
    Write-HawkLog "named_pipes: enumeration failed: $_" 'ERROR'
}

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'named_pipes' -Records $records
