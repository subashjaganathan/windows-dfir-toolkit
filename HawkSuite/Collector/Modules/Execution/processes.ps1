<#
.SYNOPSIS
    Module: processes â€” running process inventory with full lineage.
    Reference implementation of the v2 module contract.
    Migrated from windows-dfir-toolkit Running_Processes.ps1 (analysis logic removed).
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'processes: collection started'

# CIM gives CommandLine + ParentProcessId (Get-Process does not)
$cimProcs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
$byPid    = @{}
foreach ($p in $cimProcs) { $byPid[[int]$p.ProcessId] = $p }

# Owner lookup in one pass
$owners = @{}
foreach ($p in $cimProcs) {
    try {
        $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop
        if ($o.ReturnValue -eq 0) { $owners[[int]$p.ProcessId] = "$($o.Domain)\$($o.User)" }
    } catch {}
}

$records = foreach ($p in $cimProcs) {
    $procId = [int]$p.ProcessId
    $parent = $byPid[[int]$p.ParentProcessId]
    $identity = if ($p.ExecutablePath) { Get-HawkFileIdentity -Path $p.ExecutablePath }
                else { @{ path = $null; sha256 = $null; md5 = $null; signatureStatus = 'Unknown'; signer = $null } }

    [ordered]@{
        pid             = $procId
        ppid            = [int]$p.ParentProcessId
        name            = $p.Name
        path            = $p.ExecutablePath
        commandLine     = $p.CommandLine          # never truncated (contract Â§7)
        user            = $owners[$procId]
        sessionId       = [int]$p.SessionId
        startTimeUtc    = ConvertTo-HawkUtc $p.CreationDate
        sha256          = $identity.sha256
        md5             = $identity.md5
        signatureStatus = $identity.signatureStatus
        signer          = $identity.signer
        parentName      = if ($parent) { $parent.Name } else { $null }
        parentPath      = if ($parent) { $parent.ExecutablePath } else { $null }
    }
}

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'processes' -Records $records
