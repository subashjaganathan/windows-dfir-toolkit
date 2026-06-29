<#
.SYNOPSIS
    Module: scheduled_tasks â€” one record per task exec action, with binary identity.
    Migrated from windows-dfir-toolkit Scheduled_Tasks.ps1 (analysis logic removed).
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'scheduled_tasks: collection started'
$records = New-Object System.Collections.Generic.List[object]

if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
    foreach ($t in (Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        $info = $null
        try { $info = $t | Get-ScheduledTaskInfo -ErrorAction Stop } catch {}
        $principal = $t.Principal
        $author = $null
        if ($t.PSObject.Properties['Author']) { $author = $t.Author }
        elseif ($t.PSObject.Properties['RegistrationInfo'] -and $t.RegistrationInfo) { $author = $t.RegistrationInfo.Author }

        $actions = @($t.Actions | Where-Object { $_.PSObject.Properties['Execute'] -and $_.Execute })
        if (-not $actions) { $actions = @($null) }   # record COM-handler/no-exec tasks too

        foreach ($a in $actions) {
            $exec = $(if ($a) { $a.Execute } else { $null })
            $args = $(if ($a -and $a.PSObject.Properties['Arguments']) { $a.Arguments } else { $null })
            $exePath = $(if ($exec) { Resolve-HawkCommandPath ("$exec $args".Trim()) } else { $null })
            if (-not $exePath -and $exec) { $exePath = Resolve-HawkCommandPath $exec }
            $identity = if ($exePath) { Get-HawkFileIdentity -Path $exePath }
                        else { @{ sha256 = $null; md5 = $null; signatureStatus = 'Unknown'; signer = $null } }
            $records.Add([ordered]@{
                taskName        = $t.TaskName
                taskPath        = $t.TaskPath
                state           = "$($t.State)"
                author          = $author
                runAs           = $(if ($principal) { $principal.UserId } else { $null })
                runLevel        = $(if ($principal) { "$($principal.RunLevel)" } else { $null })
                execute         = $exec               # raw, never truncated
                arguments       = $args
                workingDirectory= $(if ($a -and $a.PSObject.Properties['WorkingDirectory']) { $a.WorkingDirectory } else { $null })
                binaryPath      = $exePath
                sha256          = $identity.sha256
                md5             = $identity.md5
                signatureStatus = $identity.signatureStatus
                signer          = $identity.signer
                lastRunTimeUtc  = $(if ($info) { ConvertTo-HawkUtc $info.LastRunTime } else { $null })
                nextRunTimeUtc  = $(if ($info) { ConvertTo-HawkUtc $info.NextRunTime } else { $null })
                lastTaskResult  = $(if ($info) { $info.LastTaskResult } else { $null })
                triggers        = @($t.Triggers | ForEach-Object { "$($_.CimClass.CimClassName)" }) -join ';'
            })
        }
    }
} else {
    # Win7 fallback: schtasks CSV (less detail, still raw observations)
    Write-HawkLog 'scheduled_tasks: ScheduledTasks module unavailable, using schtasks fallback' 'WARN'
    $csv = schtasks /query /v /fo csv 2>$null | ConvertFrom-Csv
    foreach ($row in $csv) {
        if ($row.TaskName -eq 'TaskName') { continue }
        $exec = $row.'Task To Run'
        $exePath = Resolve-HawkCommandPath $exec
        $identity = if ($exePath) { Get-HawkFileIdentity -Path $exePath }
                    else { @{ sha256 = $null; md5 = $null; signatureStatus = 'Unknown'; signer = $null } }
        $records.Add([ordered]@{
            taskName = (Split-Path $row.TaskName -Leaf); taskPath = (Split-Path $row.TaskName) + '\'
            state = $row.Status; author = $row.Author; runAs = $row.'Run As User'; runLevel = $null
            execute = $exec; arguments = $null; workingDirectory = $null
            binaryPath = $exePath; sha256 = $identity.sha256; md5 = $identity.md5
            signatureStatus = $identity.signatureStatus; signer = $identity.signer
            lastRunTimeUtc = ConvertTo-HawkUtc $row.'Last Run Time'; nextRunTimeUtc = ConvertTo-HawkUtc $row.'Next Run Time'
            lastTaskResult = $row.'Last Result'; triggers = $row.'Schedule Type'
        })
    }
}

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'scheduled_tasks' -Records $records
